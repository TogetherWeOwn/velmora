//! `impl JobSink` over Queues. A `Job` is sent as a JSON message. Post jobs
//! go to a post queue (`POST_Q`, and `POST_Q2`, `POST_Q3`, ... where they
//! are bound); verify, release, gc and recovery-copy jobs go to a verify
//! queue (`VERIFY_Q`, `VERIFY_Q2`, ...). An extent's job always goes to
//! the same queue of its kind ([`shard`]).
//!
//! Dev only: `DEV_DROP_NOTIFY_N` makes the first `n` `send` calls of the
//! isolate fail without sending (a queue that refuses the notification),
//! so the local acceptance run can prove that the handler leaves the
//! outbox row unmarked and the next run of the cron dispatcher sends its
//! job. (A notification lost after the queue took it is made up for only
//! when its mark has aged, an hour or more: the native tests cover that
//! with their own clock.) `send_many` is never dropped; the dispatcher
//! must keep re-enqueueing extents through it so the re-drive itself is
//! never lost.
//! A restarted isolate re-arms the counter. Outside `ENVIRONMENT=dev` the
//! variable is ignored.

use std::borrow::Cow;
use std::sync::atomic::{AtomicU32, Ordering};

use std::time::Duration;

use futures_util::future::{join_all, select, Either};
use velmora_bridge::jobmsg::{
    ControlIntent, JobFormat, JobMessage, JobTenant, APPLY_CONTROL_DELAY_SECS,
};
use velmora_bridge::root::ControlSend;
use velmora_bridge::routing::{batches, lane, Lane, Shards};
pub use velmora_bridge::routing::{binding_name, bound_queues, AUX_Q};
use velmora_bridge::tenant_catalog::LatestSeqs;
use velmora_bridge::{
    Backlog, BridgeError, Job, JobSink, Oldest, Result, UnixMs, MAX_QUEUE_DELAY_SECS,
};
use worker::js_sys::{Function, Promise, Reflect};
use worker::wasm_bindgen::{JsCast, JsValue};
use worker::wasm_bindgen_futures::JsFuture;
use worker::{console_error, MessageBuilder, Queue, QueueContentType};

/// Queues' `sendBatch` limit.
const MAX_BATCH: usize = 100;

/// Name of the dev-only drop counter variable.
pub const DEV_DROP_NOTIFY_N: &str = "DEV_DROP_NOTIFY_N";

/// Sends still to be dropped. Read once when the isolate builds its bridge,
/// so it counts down across the isolate's requests.
#[derive(Debug, Default)]
pub struct DropNotify(AtomicU32);

impl DropNotify {
    /// `dev` is the validated environment. Outside dev the value is never
    /// read (always 0). In dev, absent or empty is 0 and anything other than
    /// a non-negative integer is refused.
    pub fn from_var(dev: bool, raw: Option<&str>) -> std::result::Result<Self, String> {
        if !dev {
            return Ok(DropNotify::default());
        }
        let n = match raw.map(str::trim) {
            None | Some("") => 0,
            Some(v) => v
                .parse::<u32>()
                .map_err(|_| format!("invalid {DEV_DROP_NOTIFY_N}"))?,
        };
        Ok(DropNotify(AtomicU32::new(n)))
    }

    /// `true` = drop this send (and count it).
    fn take(&self) -> bool {
        // A compare-exchange loop rather than `fetch_update`, which newer
        // toolchains deprecate while its replacement is above the MSRV.
        let mut n = self.0.load(Ordering::Relaxed);
        while n > 0 {
            match self
                .0
                .compare_exchange_weak(n, n - 1, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(current) => n = current,
            }
        }
        false
    }

    #[cfg(test)]
    fn remaining(&self) -> u32 {
        self.0.load(Ordering::Relaxed)
    }
}

pub struct QueueSink {
    /// Never empty.
    post: Vec<Queue>,
    /// Never empty.
    verify: Vec<Queue>,
    /// The queue of the jobs that name no extent ([`AUX_Q`]), when
    /// bound.
    aux: Option<Queue>,
    drop_notify: DropNotify,
    /// The format of the messages (`JOB_FORMAT`) and the tenant a
    /// message of `v` 2 names.
    format: (JobFormat, JobTenant),
    /// A unit's sink: the highest numbers its unit answered in the job's
    /// run, which a follow-up job carries (AM-50, L6-7d).
    latest: Option<LatestSeqs>,
}

/// The tenant fields a message names: `tenant`'s, with each number raised
/// to the unit's latest answer when the sink has one. Never lower.
fn tenant_now<'a>(tenant: &'a JobTenant, latest: Option<&LatestSeqs>) -> Cow<'a, JobTenant> {
    let (Some(latest), Some(unit)) = (latest, tenant.unit()) else {
        return Cow::Borrowed(tenant);
    };
    let seqs = latest.get();
    match JobTenant::of_unit(
        tenant.tenant(),
        unit,
        seqs.state_seq.max(tenant.state_seq()),
        seqs.keys_seq.max(tenant.keys_seq()),
    ) {
        Some(raised) => Cow::Owned(raised),
        None => Cow::Borrowed(tenant),
    }
}

/// The message of `job` in `format` for `tenant`; see
/// [`QueueSink::message`].
fn message_for<'a>(
    format: JobFormat,
    tenant: &'a JobTenant,
    job: &'a Job,
) -> Result<JobMessage<'a>> {
    match format.message(job, tenant) {
        JobMessage::Plain(_) if tenant.unit().is_some() => Err(BridgeError::Queue(
            "a unit's job must be sent in the tenant format".into(),
        )),
        message => Ok(message),
    }
}

impl QueueSink {
    /// `post` and `verify` hold the queues of each kind in binding order,
    /// at least one each: an empty list is refused, with the name of the
    /// first binding of the kind. `aux` is the queue bound as [`AUX_Q`].
    pub fn new(
        post: Vec<Queue>,
        verify: Vec<Queue>,
        aux: Option<Queue>,
        drop_notify: DropNotify,
        format: (JobFormat, JobTenant),
    ) -> std::result::Result<Self, &'static str> {
        if post.is_empty() {
            return Err("POST_Q");
        }
        if verify.is_empty() {
            return Err("VERIFY_Q");
        }
        Ok(QueueSink {
            post,
            verify,
            aux,
            drop_notify,
            format,
            latest: None,
        })
    }

    /// A unit's sink: its messages carry the unit's latest numbers.
    pub fn with_latest(mut self, latest: LatestSeqs) -> Self {
        self.latest = Some(latest);
        self
    }

    /// The message that carries `job`. A sink of a managed tenant's unit
    /// (its tenant fields name a unit) sends `v` 2 only: a `v` 1 message
    /// names no tenant and is read as tenant 0's, so a job of another
    /// body version is refused here, never sent as tenant 0's.
    fn message<'a>(&self, tenant: &'a JobTenant, job: &'a Job) -> Result<JobMessage<'a>> {
        message_for(self.format.0, tenant, job)
    }

    fn tenant(&self) -> Cow<'_, JobTenant> {
        tenant_now(&self.format.1, self.latest.as_ref())
    }

    fn shards(&self) -> Shards {
        Shards {
            post: self.post.len(),
            verify: self.verify.len(),
            aux: self.aux.is_some(),
        }
    }

    fn queue(&self, lane: Lane) -> &Queue {
        match lane {
            Lane::Post(shard) => &self.post[shard],
            Lane::Verify(shard) => &self.verify[shard],
            // `lane` names it only when it is bound.
            Lane::Aux => self.aux.as_ref().unwrap_or(&self.verify[0]),
        }
    }
}

fn check_delay(delay_secs: u32) -> Result<()> {
    if delay_secs > MAX_QUEUE_DELAY_SECS {
        return Err(BridgeError::Queue(format!(
            "delay {delay_secs} s above {MAX_QUEUE_DELAY_SECS} s"
        )));
    }
    Ok(())
}

/// The outcome of sends that were all made: a queue that refused its
/// batch did not keep the others from getting theirs.
fn first_error<E>(sends: Vec<std::result::Result<(), E>>) -> Result<()> {
    match sends.into_iter().find_map(|sent| sent.err()) {
        Some(_) => Err(BridgeError::Queue("send failed".into())),
        None => Ok(()),
    }
}

fn send_err(_: worker::Error) -> BridgeError {
    BridgeError::Queue("send failed".into())
}

/// Longest wait for one queue to say what it holds. A queue that takes
/// longer is not known, and the dispatcher goes on.
const METRICS_TIMEOUT_MS: u64 = 5_000;

/// What one queue says it holds, from two values of its metrics: the
/// number of messages it can deliver now and the time the oldest was
/// sent, in ms.
///
/// The queues were seen to leave a message that waits out a delay out
/// of the count while they name its time. A job the dispatcher sends
/// has no delay, and the queues that take them always hold delayed
/// messages of other kinds (a wake-up waits up to twelve hours). So a
/// count of zero is an empty queue for the dispatcher, whatever time is
/// named: nothing it sent can be waiting there. With messages to
/// deliver, the time is that of the oldest message, delayed or not;
/// without a time that can be one, the queue is not known.
fn oldest_of(count: Option<f64>, oldest_ms: Option<f64>) -> Oldest {
    match (count, oldest_ms) {
        (Some(0.0), _) => Oldest::Empty,
        // Under 2^53: an exact integer.
        (Some(n), Some(ms))
            if n.is_finite() && n > 0.0 && (1.0..9_007_199_254_740_992.0).contains(&ms) =>
        {
            Oldest::At(UnixMs(ms as i64))
        }
        _ => Oldest::Unknown,
    }
}

/// The oldest message in the queues of one kind. One queue that is not
/// known makes the kind unknown: the message of a row may be in it.
fn oldest_in(queues: impl IntoIterator<Item = Oldest>) -> Oldest {
    let mut oldest = Oldest::Empty;
    for queue in queues {
        oldest = match (oldest, queue) {
            (_, Oldest::Unknown) => return Oldest::Unknown,
            (kept, Oldest::Empty) => kept,
            (Oldest::At(a), Oldest::At(b)) => Oldest::At(a.min(b)),
            (_, at) => at,
        };
    }
    oldest
}

/// The realtime metrics of one queue (`metrics()` of the binding).
/// `None` for a runtime without them, a call that failed and an answer
/// in another shape.
async fn metrics(queue: &Queue) -> Option<(Option<f64>, Option<f64>)> {
    let binding: &JsValue = queue.as_ref();
    let call = Reflect::get(binding, &JsValue::from_str("metrics")).ok()?;
    let call: Function = call.dyn_into().ok()?;
    let promise: Promise = call.call0(binding).ok()?.dyn_into().ok()?;
    let answer = JsFuture::from(promise).await.ok()?;
    let field = |name: &str| Reflect::get(&answer, &JsValue::from_str(name)).ok();
    let count = field("backlogCount").and_then(|v| v.as_f64());
    // A `Date`, whose value is the time in ms; absent for a queue that
    // holds nothing. Anything else is a time that cannot be one.
    let oldest_ms = field("oldestMessageTimestamp")
        .filter(|v| !v.is_undefined() && !v.is_null())
        .map(|v| {
            let date = || v.dyn_ref::<worker::js_sys::Date>().map(|d| d.get_time());
            v.as_f64().or_else(date).unwrap_or(f64::NAN)
        });
    Some((count, oldest_ms))
}

/// What one queue holds, or unknown after [`METRICS_TIMEOUT_MS`].
async fn oldest_of_queue(queue: &Queue) -> Oldest {
    let asked = Box::pin(metrics(queue));
    let limit = Box::pin(worker::Delay::from(Duration::from_millis(
        METRICS_TIMEOUT_MS,
    )));
    match select(asked, limit).await {
        Either::Left((Some((count, oldest_ms)), _)) => oldest_of(count, oldest_ms),
        _ => Oldest::Unknown,
    }
}

impl JobSink for QueueSink {
    /// One metrics call per post and verify queue, all at once. A kind
    /// that is not known is said in the log, by its name alone.
    async fn backlog(&self) -> Backlog {
        let (post, verify) = futures_util::future::join(
            join_all(self.post.iter().map(oldest_of_queue)),
            join_all(self.verify.iter().map(oldest_of_queue)),
        )
        .await;
        let backlog = Backlog {
            post: oldest_in(post),
            verify: oldest_in(verify),
        };
        for (kind, oldest) in [("post", backlog.post), ("verify", backlog.verify)] {
            if oldest == Oldest::Unknown {
                console_error!("dispatch: what the {kind} queues hold is not known");
            }
        }
        backlog
    }

    async fn send(&self, job: &Job, delay_secs: u32) -> Result<()> {
        check_delay(delay_secs)?;
        if self.drop_notify.take() {
            return Err(BridgeError::Queue("dev: send refused".to_string()));
        }
        let tenant = self.tenant();
        let msg = MessageBuilder::new(self.message(&tenant, job)?)
            .content_type(QueueContentType::Json)
            .delay_seconds(delay_secs)
            .build();
        self.queue(lane(job, self.shards()))
            .send(msg)
            .await
            .map_err(send_err)
    }

    /// One batch per queue, every queue tried. An `Err` may come with
    /// sent batches; the
    /// dispatcher re-drives from the outbox and a duplicate job only finds
    /// its lease taken.
    async fn send_many(&self, jobs: &[Job]) -> Result<()> {
        if jobs.len() > MAX_BATCH {
            return Err(BridgeError::Queue(format!("batch above {MAX_BATCH} jobs")));
        }
        let shards = self.shards();
        let tenant = self.tenant();
        let mut sends = Vec::new();
        for (target, batch) in batches(jobs, shards) {
            let batch: Vec<JobMessage<'_>> = batch
                .into_iter()
                .map(|job| self.message(&tenant, job))
                .collect::<Result<_>>()?;
            sends.push(self.queue(target).send_batch(batch).await);
        }
        first_error(sends)
    }
}

/// A control intent (`apply_control`, ADR §2.5 step 1) with its delay,
/// on the queue of the jobs that name no extent (the first verify queue
/// when [`AUX_Q`] is not bound). Every queue's consumer reads it.
impl ControlSend for QueueSink {
    async fn send_control(&self, intent: &ControlIntent) -> Result<()> {
        check_delay(APPLY_CONTROL_DELAY_SECS)?;
        let msg = MessageBuilder::new(intent.message())
            .content_type(QueueContentType::Json)
            .delay_seconds(APPLY_CONTROL_DELAY_SECS)
            .build();
        self.queue(Lane::Aux).send(msg).await.map_err(send_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use velmora_bridge::JOB_VERSION;

    /// A unit's sink never sends a `v` 1 message, which would be read as
    /// tenant 0's (tenant 0's sink, which names no unit, is unchanged).
    #[test]
    fn a_units_sink_sends_the_tenant_format_only() {
        let unit = JobTenant::of_unit("t_00000000000000a7", 0, 5, 6).unwrap();
        let current = Job::Gc { v: JOB_VERSION };
        let other = Job::Gc { v: JOB_VERSION + 7 };
        assert!(matches!(
            message_for(JobFormat::Tenant, &unit, &current),
            Ok(JobMessage::Tenant(_))
        ));
        for (format, job) in [
            (JobFormat::Tenant, &other),
            (JobFormat::Plain, &current),
            (JobFormat::Plain, &other),
        ] {
            assert!(
                message_for(format, &unit, job).is_err(),
                "{format:?} {job:?}"
            );
        }
    }

    /// A follow-up job carries the unit's latest numbers, never lower
    /// than its own. Tenant 0's sink names no unit and has no latest
    /// numbers (`tenant_now` returns its fields as they are).
    #[test]
    fn a_units_follow_up_carries_the_latest_numbers() {
        let unit = JobTenant::of_unit("t_00000000000000a7", 0, 5, 6).unwrap();
        let latest = LatestSeqs::new(velmora_bridge::unit::Seqs {
            state_seq: 7,
            keys_seq: 2,
        });
        let now = tenant_now(&unit, Some(&latest));
        assert_eq!((now.state_seq(), now.keys_seq()), (7, 6));
        assert_eq!((now.tenant(), now.unit()), ("t_00000000000000a7", Some(0)));
        assert_eq!(*tenant_now(&unit, None), unit);
    }

    /// A queue is empty, holds messages from a known time on, or is not
    /// known; a count without a time, and garbage, are not known.
    #[test]
    fn a_queue_says_what_it_holds_or_is_not_known() {
        const SENT: f64 = 1_762_992_000_123.0;
        let at = Oldest::At(UnixMs(1_762_992_000_123));
        assert_eq!(oldest_of(Some(3.0), Some(SENT)), at);
        // Nothing to deliver: empty, also when messages that wait out
        // a delay are named by their time, or the time is none.
        for oldest_ms in [None, Some(SENT), Some(0.0), Some(f64::NAN)] {
            assert_eq!(oldest_of(Some(0.0), oldest_ms), Oldest::Empty);
        }
        for (count, oldest_ms) in [
            (None, None),
            (None, Some(SENT)),
            (Some(3.0), None),
            (Some(-1.0), None),
            (Some(-1.0), Some(SENT)),
            (Some(f64::NAN), None),
            (Some(f64::NAN), Some(SENT)),
            (Some(f64::INFINITY), Some(SENT)),
            // A queue that names the epoch for its oldest message, or
            // a time that is none.
            (Some(3.0), Some(0.0)),
            (Some(3.0), Some(-1.0)),
            (Some(3.0), Some(f64::NAN)),
            (Some(3.0), Some(f64::INFINITY)),
            (Some(3.0), Some(1e300)),
        ] {
            assert_eq!(
                oldest_of(count, oldest_ms),
                Oldest::Unknown,
                "{count:?} {oldest_ms:?}"
            );
        }
    }

    /// The oldest message of a kind is the oldest of its queues, and
    /// one queue that is not known makes the kind unknown.
    #[test]
    fn a_kind_is_as_old_as_its_oldest_queue() {
        let at = |ms| Oldest::At(UnixMs(ms));
        assert_eq!(oldest_in([]), Oldest::Empty);
        assert_eq!(oldest_in([Oldest::Empty, Oldest::Empty]), Oldest::Empty);
        assert_eq!(oldest_in([Oldest::Empty, at(7), Oldest::Empty]), at(7));
        assert_eq!(oldest_in([at(9), at(7), at(8)]), at(7));
        for unknown in [
            vec![Oldest::Unknown],
            vec![at(7), Oldest::Unknown],
            vec![Oldest::Unknown, at(7)],
            vec![Oldest::Empty, Oldest::Unknown, Oldest::Empty],
        ] {
            assert_eq!(oldest_in(unknown.clone()), Oldest::Unknown, "{unknown:?}");
        }
    }

    #[test]
    fn sends_report_the_first_failure_after_all_were_made() {
        assert!(first_error::<&str>(vec![]).is_ok());
        assert!(first_error::<&str>(vec![Ok(()), Ok(())]).is_ok());
        let failed = first_error(vec![Ok(()), Err("second queue"), Ok(())]);
        assert!(matches!(failed, Err(BridgeError::Queue(_))));
    }

    #[test]
    fn drop_counter_drops_exactly_n_then_passes() {
        let d = DropNotify::from_var(true, Some("2")).unwrap();
        assert_eq!(d.remaining(), 2);
        assert!(d.take());
        assert!(d.take());
        assert!(!d.take(), "after n drops, sends go through");
        assert!(!d.take());
        assert_eq!(d.remaining(), 0);
    }

    #[test]
    fn drop_counter_in_dev_defaults_to_zero_and_refuses_garbage() {
        for raw in [None, Some(""), Some(" "), Some("0")] {
            let d = DropNotify::from_var(true, raw).unwrap();
            assert!(!d.take(), "{raw:?}");
        }
        assert!(DropNotify::from_var(true, Some(" 1 ")).unwrap().take());
        for raw in ["-1", "x", "1.5", "4294967296"] {
            // The refusal names the variable, never the value.
            let err = DropNotify::from_var(true, Some(raw)).unwrap_err();
            assert_eq!(err, "invalid DEV_DROP_NOTIFY_N");
        }
    }

    #[test]
    fn drop_counter_is_ignored_outside_dev() {
        // Prod never drops, whatever the variable says, and never refuses.
        for raw in [None, Some("1"), Some("1000"), Some("garbage")] {
            let d = DropNotify::from_var(false, raw).unwrap();
            assert_eq!(d.remaining(), 0, "{raw:?}");
            assert!(!d.take(), "{raw:?}");
        }
    }

    #[test]
    fn delay_is_capped_at_twelve_hours() {
        assert!(check_delay(0).is_ok());
        assert!(check_delay(MAX_QUEUE_DELAY_SECS).is_ok());
        assert!(matches!(
            check_delay(MAX_QUEUE_DELAY_SECS + 1),
            Err(BridgeError::Queue(_))
        ));
    }
}
