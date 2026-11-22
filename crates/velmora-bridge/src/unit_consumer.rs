//! What the queue consumer does with a managed tenant's job (ADR-TENANCY
//! §2.4 rule 5, as AM-50 of design round 5 states it).
//!
//! The job runs over a [`crate::tenant_catalog::TenantCatalog`], which
//! keeps the first refusal the unit gave in the run
//! ([`crate::tenant_catalog::TenantCatalog::refusal`]). When there is one,
//! it decides the delivery, whatever `run_job` answered:
//!
//! | The unit answers | The consumer |
//! |---|---|
//! | `Stale{seqs}` | runs the job once more with the unit's `seqs`. A second `Stale` is acknowledged; the outbox row stays in the unit |
//! | `Refused{stale_job}` (no numbers) | dead-letter queue and page: no writer sends a format-2 job without numbers |
//! | `Closed` (restoring, provisioning) | acknowledged; the row stays in the unit's outbox, and its dispatcher sends it again once the unit opens |
//! | `renew_needed` | renews through the unit client, then runs the job once more. A failed renewal hands the message back with the queue's `retry_delay` |
//! | `SyncNeeded` | syncs through the unit client (both chains read and verified, the keys applied, then `sync`), then runs the job once more with the unit's new numbers. A failure hands the message back; the dead-letter queue pages once `max_retries` is reached |
//! | `Unborn` | reads the tenant's verified head. Listed: dead-letter queue and a "catalogue lost" page (rule 7). Not listed: acknowledged, no page. A head read that fails or does not verify hands the message back and never acknowledges |
//! | `AccountProblem` while the tenant is `shredding` or `shredded` | acknowledged with a log line, no page (the head says the state; a failed read hands back) |
//! | any other refusal | dead-letter queue and page |
//!
//! A job runs once more at most once per delivery. A `renew_needed` or a
//! `SyncNeeded` after that run hands the message back.
//!
//! **Maintenance.** A managed tenant's job config keeps tenant 0's
//! `MAINTENANCE` (`BridgeConfig::for_unit`). Under `restore` no unit job
//! makes a unit call: an outbox job is acknowledged and its row stays;
//! `renew` and `stamp_raise` are acknowledged with a log line and no page
//! (a hand-back with the 0 s refused-retry delay would page within
//! seconds, through the whole window). DS1 §3.4 depends on this from 8(b)
//! to step 9.
//!
//! `renew` and `stamp_raise` ([`UnitJob`]) have no outbox row. They run
//! through the unit client; a failure hands the message back with the
//! queue's `retry_delay`.
//!
//! No delivery is dropped in silence: each decision is one log line with
//! a fixed code ([`Line`]), an alert for the ones that page. Nothing here
//! reads or writes a catalogue itself.

use crate::config::Maintenance;
use crate::jobmsg::{UnitJob, REFUSED_RETRY_DELAY_SECS};
use crate::tenant_catalog::UnitRefusal;
use crate::types::{JobOutcome, Result};
use crate::unit::{Seqs, UnitName};
use crate::unit_router::TenantHeads;

/// What the consumer does with the message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    Ack,
    /// Hand it back after `delay_secs`.
    Retry {
        delay_secs: u32,
    },
    /// Hand it back with the queue's own `retry_delay` (no delay option).
    HandBack,
}

impl Delivery {
    fn of(outcome: JobOutcome) -> Delivery {
        match outcome {
            JobOutcome::Ack => Delivery::Ack,
            JobOutcome::Retry { delay_secs } => Delivery::Retry { delay_secs },
        }
    }

    /// To the dead-letter queue within seconds, which pages.
    const DEAD_LETTER: Delivery = Delivery::Retry {
        delay_secs: REFUSED_RETRY_DELAY_SECS,
    };
}

/// The log line of a decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Line {
    /// A fixed word: never a field of the message or a unit's text.
    pub code: &'static str,
    /// The line is an alert: the message goes to the dead-letter queue.
    pub alert: bool,
}

const fn line(code: &'static str, alert: bool) -> Option<Line> {
    Some(Line { code, alert })
}

/// The unit client as the consumer calls it: the Worker side of `renew`
/// and `sync`, and the `stamp_raise` handler (lane L2, design round 5
/// §R5-4). L2's unit client implements it; a build without one uses
/// [`NoClient`].
#[allow(async_fn_in_trait)]
pub trait ConsumerClient {
    /// Proves the unit's lease from the stores and calls `renew` (rule
    /// 12). Also the `renew` job.
    async fn renew(&self, unit: &UnitName) -> Result<()>;
    /// Reads and verifies both chains up to their heads, applies the keys
    /// (AM-12) and calls `sync`. Answers the unit's numbers after it.
    async fn sync(&self, unit: &UnitName) -> Result<Seqs>;
    /// The `stamp_raise` job (§8.5, AM-48).
    async fn stamp_raise(&self, unit: &UnitName) -> Result<()>;
}

/// No unit client in this build: every call fails, so the message is
/// handed back and reaches the dead-letter queue, which pages.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoClient;

/// The error of [`NoClient`].
pub const NO_UNIT_CLIENT: &str = "no unit client in this build";

impl ConsumerClient for NoClient {
    async fn renew(&self, _: &UnitName) -> Result<()> {
        Err(crate::types::BridgeError::NotImplemented(NO_UNIT_CLIENT))
    }
    async fn sync(&self, _: &UnitName) -> Result<Seqs> {
        Err(crate::types::BridgeError::NotImplemented(NO_UNIT_CLIENT))
    }
    async fn stamp_raise(&self, _: &UnitName) -> Result<()> {
        Err(crate::types::BridgeError::NotImplemented(NO_UNIT_CLIENT))
    }
}

/// One run of the job against its unit.
#[allow(async_fn_in_trait)]
pub trait UnitRun {
    /// Runs the job with its calls carrying `seqs`, and answers its
    /// outcome and the first refusal the unit gave in that run.
    async fn run(&self, seqs: Seqs) -> (JobOutcome, Option<UnitRefusal>);
}

/// The delivery of a managed tenant's outbox job (see the
/// [module](self)). `seqs`: the message's numbers.
pub async fn deliver<R: UnitRun, C: ConsumerClient, H: TenantHeads>(
    maintenance: Maintenance,
    unit: &UnitName,
    seqs: Seqs,
    run: &R,
    client: &C,
    heads: &H,
) -> (Delivery, Option<Line>) {
    if maintenance == Maintenance::Restore {
        // No unit call: the row stays in the unit's outbox.
        return (Delivery::Ack, line("maintenance", false));
    }
    let mut seqs = seqs;
    let mut again = false;
    loop {
        let (outcome, refusal) = run.run(seqs).await;
        let Some(refusal) = refusal else {
            return (Delivery::of(outcome), None);
        };
        match refusal {
            UnitRefusal::Stale(unit_seqs) if !again => seqs = unit_seqs,
            UnitRefusal::Stale(_) => return (Delivery::Ack, line("stale_again", false)),
            UnitRefusal::StaleJob => {
                return (Delivery::DEAD_LETTER, line("stale_job_no_numbers", true))
            }
            UnitRefusal::Closed => return (Delivery::Ack, line("closed", false)),
            UnitRefusal::RenewNeeded if !again => {
                if client.renew(unit).await.is_err() {
                    return (Delivery::HandBack, line("renew_failed", false));
                }
            }
            UnitRefusal::RenewNeeded => {
                return (Delivery::HandBack, line("renew_needed_again", false))
            }
            UnitRefusal::SyncNeeded if !again => match client.sync(unit).await {
                Ok(unit_seqs) => seqs = unit_seqs,
                Err(_) => return (Delivery::HandBack, line("sync_failed", false)),
            },
            UnitRefusal::SyncNeeded => {
                return (Delivery::HandBack, line("sync_needed_again", false))
            }
            UnitRefusal::Unborn => {
                return match heads.head(&unit.tenant).await {
                    Ok(head) if head.lists(unit) => {
                        (Delivery::DEAD_LETTER, line("catalogue_lost", true))
                    }
                    Ok(_) => (Delivery::Ack, line("unborn_unlisted", false)),
                    Err(_) => (Delivery::HandBack, line("unborn_head_unread", false)),
                }
            }
            UnitRefusal::AccountProblem => {
                return match heads.head(&unit.tenant).await {
                    Ok(head) if head.shredding() => (Delivery::Ack, line("shredding", false)),
                    Ok(_) => (Delivery::DEAD_LETTER, line("account_problem", true)),
                    Err(_) => (Delivery::HandBack, line("account_head_unread", false)),
                }
            }
            UnitRefusal::Other => return (Delivery::DEAD_LETTER, line("refused", true)),
        }
        again = true;
    }
}

/// The delivery of a unit job (`renew`, `stamp_raise`): no outbox row, no
/// catalogue. Under `restore` it makes no call and is acknowledged with
/// no page (see the [module](self)).
pub async fn deliver_unit_job<C: ConsumerClient>(
    maintenance: Maintenance,
    job: UnitJob,
    unit: &UnitName,
    client: &C,
) -> (Delivery, Line) {
    let (code, failed) = match job {
        UnitJob::Renew { .. } => ("renew", "renew_failed"),
        UnitJob::StampRaise { .. } => ("stamp_raise", "stamp_raise_failed"),
    };
    if maintenance == Maintenance::Restore {
        return (
            Delivery::Ack,
            Line {
                code: "maintenance",
                alert: false,
            },
        );
    }
    let done = match job {
        UnitJob::Renew { .. } => client.renew(unit).await,
        UnitJob::StampRaise { .. } => client.stamp_raise(unit).await,
    };
    match done {
        Ok(()) => (Delivery::Ack, Line { code, alert: false }),
        Err(_) => (
            Delivery::HandBack,
            Line {
                code: failed,
                alert: false,
            },
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BridgeError, UnixMs};
    use crate::unit::{TenantId, TenantState};
    use crate::unit_router::{HeadView, NoHeads};
    use std::cell::{Cell, RefCell};

    fn unit() -> UnitName {
        UnitName::new(TenantId::parse("t_00000000000000a7").unwrap(), 0)
    }

    fn seqs(state_seq: u64, keys_seq: u64) -> Seqs {
        Seqs {
            state_seq,
            keys_seq,
        }
    }

    /// A run that answers the given refusals in turn, then none; it keeps
    /// the numbers each run carried.
    struct Script {
        answers: RefCell<Vec<Option<UnitRefusal>>>,
        carried: RefCell<Vec<Seqs>>,
        outcome: JobOutcome,
    }

    impl Script {
        fn new(answers: &[Option<UnitRefusal>]) -> Script {
            Script {
                answers: RefCell::new(answers.iter().rev().copied().collect()),
                carried: RefCell::default(),
                outcome: JobOutcome::Retry { delay_secs: 30 },
            }
        }
        fn runs(&self) -> Vec<Seqs> {
            self.carried.borrow().clone()
        }
    }

    impl UnitRun for Script {
        async fn run(&self, seqs: Seqs) -> (JobOutcome, Option<UnitRefusal>) {
            self.carried.borrow_mut().push(seqs);
            let next = self.answers.borrow_mut().pop().flatten();
            (self.outcome, next)
        }
    }

    #[derive(Default)]
    struct Client {
        fail: bool,
        renews: Cell<u32>,
        syncs: Cell<u32>,
        raises: Cell<u32>,
        after_sync: Option<Seqs>,
    }

    impl ConsumerClient for Client {
        async fn renew(&self, _: &UnitName) -> Result<()> {
            self.renews.set(self.renews.get() + 1);
            match self.fail {
                true => Err(BridgeError::Sql("down".into())),
                false => Ok(()),
            }
        }
        async fn sync(&self, _: &UnitName) -> Result<Seqs> {
            self.syncs.set(self.syncs.get() + 1);
            match self.fail {
                true => Err(BridgeError::Sql("down".into())),
                false => Ok(self.after_sync.unwrap_or(seqs(9, 9))),
            }
        }
        async fn stamp_raise(&self, _: &UnitName) -> Result<()> {
            self.raises.set(self.raises.get() + 1);
            match self.fail {
                true => Err(BridgeError::Sql("down".into())),
                false => Ok(()),
            }
        }
    }

    struct Heads(Option<HeadView>, Cell<u32>);

    impl Heads {
        fn of(state: TenantState, units: &[u32]) -> Heads {
            Heads(
                Some(HeadView {
                    seqs: seqs(3, 1),
                    state,
                    units: units.to_vec(),
                }),
                Cell::new(0),
            )
        }
        fn failing() -> Heads {
            Heads(None, Cell::new(0))
        }
    }

    impl TenantHeads for Heads {
        async fn head(&self, _: &TenantId) -> Result<HeadView> {
            self.1.set(self.1.get() + 1);
            self.0.clone().ok_or(BridgeError::Sql("unreadable".into()))
        }
    }

    async fn go(script: &Script, client: &Client, heads: &Heads) -> (Delivery, Option<Line>) {
        deliver(Maintenance::Off, &unit(), seqs(3, 1), script, client, heads).await
    }

    fn code(l: Option<Line>) -> (&'static str, bool) {
        let l = l.expect("a line");
        (l.code, l.alert)
    }

    #[tokio::test]
    async fn no_refusal_keeps_the_jobs_outcome() {
        let s = Script::new(&[None]);
        let (d, l) = go(&s, &Client::default(), &Heads::failing()).await;
        assert_eq!(d, Delivery::Retry { delay_secs: 30 });
        assert_eq!(l, None);
        assert_eq!(s.runs(), [seqs(3, 1)]);
    }

    #[tokio::test]
    async fn stale_runs_once_more_with_the_units_numbers_then_acknowledges() {
        let s = Script::new(&[Some(UnitRefusal::Stale(seqs(5, 2))), None]);
        let (d, l) = go(&s, &Client::default(), &Heads::failing()).await;
        assert_eq!(d, Delivery::Retry { delay_secs: 30 });
        assert_eq!(l, None);
        assert_eq!(s.runs(), [seqs(3, 1), seqs(5, 2)]);

        let s = Script::new(&[
            Some(UnitRefusal::Stale(seqs(5, 2))),
            Some(UnitRefusal::Stale(seqs(6, 2))),
        ]);
        let (d, l) = go(&s, &Client::default(), &Heads::failing()).await;
        assert_eq!(d, Delivery::Ack);
        assert_eq!(code(l), ("stale_again", false));
        assert_eq!(s.runs().len(), 2);
    }

    #[tokio::test]
    async fn a_job_without_numbers_pages() {
        let s = Script::new(&[Some(UnitRefusal::StaleJob)]);
        let (d, l) = go(&s, &Client::default(), &Heads::failing()).await;
        assert_eq!(d, Delivery::DEAD_LETTER);
        assert_eq!(code(l), ("stale_job_no_numbers", true));
        assert_eq!(s.runs().len(), 1);
    }

    #[tokio::test]
    async fn closed_is_acknowledged() {
        let s = Script::new(&[Some(UnitRefusal::Closed)]);
        let (d, l) = go(&s, &Client::default(), &Heads::failing()).await;
        assert_eq!(d, Delivery::Ack);
        assert_eq!(code(l), ("closed", false));
    }

    #[tokio::test]
    async fn renew_needed_renews_then_runs_once_more() {
        let c = Client::default();
        let s = Script::new(&[Some(UnitRefusal::RenewNeeded), None]);
        let (d, l) = go(&s, &c, &Heads::failing()).await;
        assert_eq!((d, l), (Delivery::Retry { delay_secs: 30 }, None));
        assert_eq!(c.renews.get(), 1);
        assert_eq!(s.runs(), [seqs(3, 1), seqs(3, 1)]);
        // Renewed, and refused again: handed back, not renewed twice.
        let c = Client::default();
        let s = Script::new(&[
            Some(UnitRefusal::RenewNeeded),
            Some(UnitRefusal::RenewNeeded),
        ]);
        let (d, l) = go(&s, &c, &Heads::failing()).await;
        assert_eq!(d, Delivery::HandBack);
        assert_eq!(code(l), ("renew_needed_again", false));
        assert_eq!(c.renews.get(), 1);
        // A failed renewal hands back with the queue's delay.
        let c = Client {
            fail: true,
            ..Client::default()
        };
        let s = Script::new(&[Some(UnitRefusal::RenewNeeded)]);
        let (d, l) = go(&s, &c, &Heads::failing()).await;
        assert_eq!(d, Delivery::HandBack);
        assert_eq!(code(l), ("renew_failed", false));
        assert_eq!(s.runs().len(), 1);
    }

    #[tokio::test]
    async fn sync_needed_syncs_then_runs_once_more_with_the_new_numbers() {
        let c = Client {
            after_sync: Some(seqs(7, 4)),
            ..Client::default()
        };
        let s = Script::new(&[Some(UnitRefusal::SyncNeeded), None]);
        let (d, l) = go(&s, &c, &Heads::failing()).await;
        assert_eq!((d, l), (Delivery::Retry { delay_secs: 30 }, None));
        assert_eq!(c.syncs.get(), 1);
        assert_eq!(s.runs(), [seqs(3, 1), seqs(7, 4)]);
        let c = Client {
            fail: true,
            ..Client::default()
        };
        let s = Script::new(&[Some(UnitRefusal::SyncNeeded)]);
        let (d, l) = go(&s, &c, &Heads::failing()).await;
        assert_eq!(d, Delivery::HandBack);
        assert_eq!(code(l), ("sync_failed", false));
        let s = Script::new(&[Some(UnitRefusal::SyncNeeded), Some(UnitRefusal::SyncNeeded)]);
        let (d, l) = go(&s, &Client::default(), &Heads::failing()).await;
        assert_eq!(d, Delivery::HandBack);
        assert_eq!(code(l), ("sync_needed_again", false));
    }

    /// One run once more per delivery, whatever the mix.
    #[tokio::test]
    async fn one_run_once_more_per_delivery() {
        let c = Client::default();
        let s = Script::new(&[
            Some(UnitRefusal::Stale(seqs(5, 2))),
            Some(UnitRefusal::RenewNeeded),
        ]);
        let (d, l) = go(&s, &c, &Heads::failing()).await;
        assert_eq!(d, Delivery::HandBack);
        assert_eq!(code(l), ("renew_needed_again", false));
        assert_eq!(c.renews.get(), 0);
        assert_eq!(s.runs().len(), 2);
    }

    #[tokio::test]
    async fn unborn_is_decided_by_the_verified_head() {
        let s = Script::new(&[Some(UnitRefusal::Unborn)]);
        let h = Heads::of(TenantState::Active, &[0]);
        let (d, l) = go(&s, &Client::default(), &h).await;
        assert_eq!(d, Delivery::DEAD_LETTER);
        assert_eq!(code(l), ("catalogue_lost", true));
        let s = Script::new(&[Some(UnitRefusal::Unborn)]);
        let h = Heads::of(TenantState::Active, &[1]);
        let (d, l) = go(&s, &Client::default(), &h).await;
        assert_eq!(d, Delivery::Ack);
        assert_eq!(code(l), ("unborn_unlisted", false));
        // Never acknowledged on a head it could not read.
        let s = Script::new(&[Some(UnitRefusal::Unborn)]);
        let (d, l) = go(&s, &Client::default(), &Heads::failing()).await;
        assert_eq!(d, Delivery::HandBack);
        assert_eq!(code(l), ("unborn_head_unread", false));
        let s = Script::new(&[Some(UnitRefusal::Unborn)]);
        let (d, _) = deliver(
            Maintenance::Off,
            &unit(),
            seqs(3, 1),
            &s,
            &Client::default(),
            &NoHeads,
        )
        .await;
        assert_eq!(d, Delivery::HandBack);
    }

    #[tokio::test]
    async fn a_shred_is_acknowledged_without_a_page() {
        for state in [TenantState::Shredding, TenantState::Shredded] {
            let s = Script::new(&[Some(UnitRefusal::AccountProblem)]);
            let (d, l) = go(&s, &Client::default(), &Heads::of(state, &[])).await;
            assert_eq!(d, Delivery::Ack, "{state:?}");
            assert_eq!(code(l), ("shredding", false));
        }
        let s = Script::new(&[Some(UnitRefusal::AccountProblem)]);
        let (d, l) = go(
            &s,
            &Client::default(),
            &Heads::of(TenantState::Active, &[0]),
        )
        .await;
        assert_eq!(d, Delivery::DEAD_LETTER);
        assert_eq!(code(l), ("account_problem", true));
        let s = Script::new(&[Some(UnitRefusal::AccountProblem)]);
        let (d, l) = go(&s, &Client::default(), &Heads::failing()).await;
        assert_eq!(d, Delivery::HandBack);
        assert_eq!(code(l), ("account_head_unread", false));
    }

    #[tokio::test]
    async fn any_other_refusal_pages() {
        let s = Script::new(&[Some(UnitRefusal::Other)]);
        let (d, l) = go(&s, &Client::default(), &Heads::failing()).await;
        assert_eq!(d, Delivery::DEAD_LETTER);
        assert_eq!(code(l), ("refused", true));
    }

    /// The acceptance of L6-1: under `restore`, a unit job makes no unit
    /// call, and `renew` and `stamp_raise` are acknowledged with no alert.
    #[tokio::test]
    async fn under_restore_no_unit_call_and_no_page() {
        let s = Script::new(&[Some(UnitRefusal::Other)]);
        let c = Client::default();
        let h = Heads::failing();
        let (d, l) = deliver(Maintenance::Restore, &unit(), seqs(3, 1), &s, &c, &h).await;
        assert_eq!(d, Delivery::Ack);
        assert_eq!(code(l), ("maintenance", false));
        assert!(s.runs().is_empty());
        for job in [
            UnitJob::Renew { at: UnixMs(1) },
            UnitJob::StampRaise { at: UnixMs(1) },
        ] {
            let (d, l) = deliver_unit_job(Maintenance::Restore, job, &unit(), &c).await;
            assert_eq!(d, Delivery::Ack);
            assert_eq!((l.code, l.alert), ("maintenance", false));
        }
        assert_eq!((c.renews.get(), c.syncs.get(), c.raises.get()), (0, 0, 0));
        assert_eq!(h.1.get(), 0);
    }

    #[tokio::test]
    async fn unit_jobs_run_through_the_client() {
        let c = Client::default();
        let (d, l) = deliver_unit_job(
            Maintenance::Off,
            UnitJob::Renew { at: UnixMs(1) },
            &unit(),
            &c,
        )
        .await;
        assert_eq!((d, l.code, l.alert), (Delivery::Ack, "renew", false));
        let (d, l) = deliver_unit_job(
            Maintenance::Off,
            UnitJob::StampRaise { at: UnixMs(1) },
            &unit(),
            &c,
        )
        .await;
        assert_eq!((d, l.code, l.alert), (Delivery::Ack, "stamp_raise", false));
        assert_eq!((c.renews.get(), c.raises.get()), (1, 1));
        // A failure hands back with the queue's delay; so does this build,
        // which has no client.
        let failing = Client {
            fail: true,
            ..Client::default()
        };
        for client_fails in [true, false] {
            let (d, l) = match client_fails {
                true => {
                    deliver_unit_job(
                        Maintenance::Off,
                        UnitJob::Renew { at: UnixMs(1) },
                        &unit(),
                        &failing,
                    )
                    .await
                }
                false => {
                    deliver_unit_job(
                        Maintenance::Off,
                        UnitJob::StampRaise { at: UnixMs(1) },
                        &unit(),
                        &NoClient,
                    )
                    .await
                }
            };
            assert_eq!(d, Delivery::HandBack);
            assert!(!l.alert);
        }
    }
}
