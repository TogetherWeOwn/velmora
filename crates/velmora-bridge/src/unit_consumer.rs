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
//! | `renew_needed` | renews through the unit client (`UnitClient::renew`), then runs the job once more. A failed renewal hands the message back with the queue's `retry_delay` |
//! | `SyncNeeded` | syncs through the unit client (`UnitClient::sync`: both chains read and verified, the keys applied, then `sync`), then runs the job once more with the higher of the message's and the unit's new numbers. A failure hands the message back; the dead-letter queue pages once `max_retries` is reached |
//! | `Unborn` | reads the tenant's verified head. Listed: dead-letter queue and a "catalogue lost" page (rule 7). Not listed: acknowledged, no page. A head read that fails or does not verify hands the message back and never acknowledges |
//! | `AccountProblem` while the tenant is `shredding` or `shredded` | acknowledged with a log line, no page (the head says the state; a failed read hands back) |
//! | any other refusal | dead-letter queue and page |
//!
//! Each fix runs at most once per delivery: the unit's numbers (`Stale`),
//! a renewal and a `sync`, so a delivery runs the job at most four times.
//! The same refusal after its fix: a second `Stale` is acknowledged, a
//! second `renew_needed` or `SyncNeeded` hands the message back. Before
//! each run once more, the outbox lease the last run took is given back
//! with the new numbers ([`UnitRun::prepare`]): the run once more must be
//! able to claim the row, or it would find it leased and acknowledge
//! having done nothing. If the lease cannot be given back, the message is
//! handed back. A run the job table gave up (it did not end in time)
//! never runs once more: its outcome stands.
//!
//! A hand-back whose lease could not be given back leaves the row leased:
//! a redelivery before the lease runs out (600 s) finds it leased and is
//! acknowledged, and the unit's dispatcher sends the row again once the
//! lease is over. That delays the work by at most the lease and one
//! dispatcher period; the row, which is the obligation, stays.
//!
//! What the unit client answers besides an error is mapped onto the same
//! rows: a renewal or a `sync` that finds the unit closed (or a lift
//! pending, which only the restore tool's `sync` may make) is the
//! `Closed` row; one that finds it unborn is the `Unborn` row; one whose
//! verified head does not list the unit is acknowledged with no page
//! (rule 7); a renewal refused for an operator pages. Every `Page` the
//! client returns is logged as an alert, by a fixed code.
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
//! through the unit client (`UnitClient::run_job`, with the message's
//! numbers): it acknowledges or hands back, and an `Unborn` takes the
//! `Unborn` row above.
//!
//! No delivery is dropped in silence: each decision is one log line with
//! a fixed code ([`Line`]), an alert for the ones that page. Nothing here
//! reads or writes a catalogue itself.

use crate::config::Maintenance;
use crate::jobmsg::{UnitJob, REFUSED_RETRY_DELAY_SECS};
use crate::ports::{BlobStore, Clock};
use crate::tenant_catalog::UnitRefusal;
use crate::types::{BridgeError, JobOutcome, Result};
use crate::unit::{Seqs, UnitName};
use crate::unit_lease::client::{
    self, JobResult, KeyFeed, KeyFinisher, Page, Renewal, Synced, TenantHeads, UnitClient,
    UnitReplies,
};
use crate::unit_lease::renewal::ChainNames;
use crate::unit_router::read_head;

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
    pub const DEAD_LETTER: Delivery = Delivery::Retry {
        delay_secs: REFUSED_RETRY_DELAY_SECS,
    };
}

/// One log line of a decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Line {
    /// A fixed word: never a field of the message or a unit's text.
    pub code: &'static str,
    /// The line is an alert (it pages).
    pub alert: bool,
}

const fn line(code: &'static str, alert: bool) -> Line {
    Line { code, alert }
}

/// The fixed code of a unit client's [`Page`], logged as an alert. The
/// names some pages carry stay out of the log line.
pub fn page_code(page: &Page) -> &'static str {
    match page {
        Page::StrayRevocationNames(_) => "stray_revocation_names",
        Page::RevocationsShort { .. } => "revocations_short",
        Page::RolledBack => "rolled_back",
        Page::RenewRefused(_) => "renew_refused",
        Page::FinisherNotTold => "finisher_not_told",
    }
}

fn pages(pages: &[Page]) -> impl Iterator<Item = Line> + '_ {
    pages.iter().map(|p| line(page_code(p), true))
}

/// The unit client as the consumer calls it: L2's
/// [`client::UnitClient`] (implemented below), or [`NoClient`] in a build
/// without one. Bound to one unit.
#[allow(async_fn_in_trait)]
pub trait ConsumerClient {
    /// `UnitClient::renew`: prove the lease and `renew` (rule 12). `seen`:
    /// the unit's numbers as its last answer gave them.
    async fn renew(&self, seen: Seqs) -> Result<(Renewal, Vec<Page>)>;
    /// `UnitClient::sync`: read and verify both chains, apply the keys
    /// (AM-12), then `sync`.
    async fn sync(&self, seen: Seqs) -> Result<Synced>;
    /// `UnitClient::run_job`: a `renew` or `stamp_raise` message at the
    /// numbers it carries.
    async fn run_job(&self, job: UnitJob, seqs: Seqs) -> JobResult;
}

impl<U, B, T, N, H, K, F> ConsumerClient for UnitClient<U, B, T, N, H, K, F>
where
    U: UnitReplies,
    B: BlobStore,
    T: Clock,
    N: ChainNames,
    H: TenantHeads,
    K: KeyFeed,
    F: KeyFinisher,
{
    async fn renew(&self, seen: Seqs) -> Result<(Renewal, Vec<Page>)> {
        UnitClient::renew(self, seen).await
    }
    async fn sync(&self, seen: Seqs) -> Result<Synced> {
        UnitClient::sync(self, seen).await
    }
    async fn run_job(&self, job: UnitJob, seqs: Seqs) -> JobResult {
        UnitClient::run_job(self, job, seqs).await
    }
}

/// No unit client in this build: every call fails, so the message is
/// handed back and reaches the dead-letter queue, which pages.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoClient;

/// The error of [`NoClient`].
pub const NO_UNIT_CLIENT: &str = "no unit client in this build";

impl ConsumerClient for NoClient {
    async fn renew(&self, _: Seqs) -> Result<(Renewal, Vec<Page>)> {
        Err(BridgeError::NotImplemented(NO_UNIT_CLIENT))
    }
    async fn sync(&self, _: Seqs) -> Result<Synced> {
        Err(BridgeError::NotImplemented(NO_UNIT_CLIENT))
    }
    async fn run_job(&self, _: UnitJob, _: Seqs) -> JobResult {
        JobResult {
            delivery: client::Delivery::HandBack,
            code: "no_unit_client",
            pages: Vec::new(),
        }
    }
}

/// What one run of the job came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ran {
    pub outcome: JobOutcome,
    /// The first refusal the unit gave in the run.
    pub refusal: Option<UnitRefusal>,
    /// The job ended; `false`: the job table gave it up (it did not end in
    /// time, or it was dropped), and `outcome` is the table's retry.
    pub finished: bool,
}

/// One run of the job against its unit.
#[allow(async_fn_in_trait)]
pub trait UnitRun {
    /// Runs the job with its calls carrying `seqs`.
    async fn run(&self, seqs: Seqs) -> Ran;
    /// Before the job runs once more with `seqs`: gives back, with `seqs`,
    /// the outbox lease the last run took and did not free. `false`: it
    /// could not be given back.
    async fn prepare(&self, seqs: Seqs) -> bool;
}

/// Each number to the higher of the two: a run once more never carries
/// numbers below the message's (a head below them is a rollback that the
/// unit must find, rule 5).
fn higher(a: Seqs, b: Seqs) -> Seqs {
    Seqs {
        state_seq: a.state_seq.max(b.state_seq),
        keys_seq: a.keys_seq.max(b.keys_seq),
    }
}

/// The `Unborn` row: the tenant's verified head decides (rule 7).
async fn unborn<H: TenantHeads>(heads: &H, unit: &UnitName) -> (Delivery, Line) {
    match read_head(heads, &unit.tenant).await {
        Ok(Some(head)) if head.lists(unit) => (Delivery::DEAD_LETTER, line("catalogue_lost", true)),
        Ok(_) => (Delivery::Ack, line("unborn_unlisted", false)),
        Err(_) => (Delivery::HandBack, line("unborn_head_unread", false)),
    }
}

/// The `AccountProblem` row: a shred stops jobs by design.
async fn account<H: TenantHeads>(heads: &H, unit: &UnitName) -> (Delivery, Line) {
    match read_head(heads, &unit.tenant).await {
        Ok(Some(head)) if head.shredding() => (Delivery::Ack, line("shredding", false)),
        Ok(_) => (Delivery::DEAD_LETTER, line("account_problem", true)),
        Err(_) => (Delivery::HandBack, line("account_head_unread", false)),
    }
}

/// What a refusal leads to: a delivery, or a run once more with numbers.
enum Next {
    Done(Delivery, Line),
    Again(Seqs),
}

/// The delivery of a managed tenant's outbox job (see the
/// [module](self)). `seqs`: the message's numbers. Every line is to be
/// logged, in order.
pub async fn deliver<R: UnitRun, C: ConsumerClient, H: TenantHeads>(
    maintenance: Maintenance,
    unit: &UnitName,
    seqs: Seqs,
    run: &R,
    client: &C,
    heads: &H,
) -> (Delivery, Vec<Line>) {
    if maintenance == Maintenance::Restore {
        // No unit call: the row stays in the unit's outbox.
        return (Delivery::Ack, vec![line("maintenance", false)]);
    }
    let mut lines = Vec::new();
    let mut seqs = seqs;
    // Each fix once per delivery.
    let (mut restamped, mut renewed, mut synced) = (false, false, false);
    loop {
        let ran = run.run(seqs).await;
        if !ran.finished {
            // The table's retry stands; a run once more would start late
            // in this invocation and could outlive it.
            lines.push(line("job_not_finished", false));
            return (Delivery::of(ran.outcome), lines);
        }
        let Some(refusal) = ran.refusal else {
            return (Delivery::of(ran.outcome), lines);
        };
        let next = match refusal {
            UnitRefusal::Stale(unit_seqs) if !restamped => {
                restamped = true;
                Next::Again(higher(seqs, unit_seqs))
            }
            UnitRefusal::Stale(_) => Next::Done(Delivery::Ack, line("stale_again", false)),
            UnitRefusal::StaleJob => {
                Next::Done(Delivery::DEAD_LETTER, line("stale_job_no_numbers", true))
            }
            UnitRefusal::Closed => Next::Done(Delivery::Ack, line("closed", false)),
            UnitRefusal::RenewNeeded(seen) if !renewed => {
                renewed = true;
                match client.renew(seen).await {
                    Err(_) => Next::Done(Delivery::HandBack, line("renew_failed", false)),
                    Ok((renewal, alerts)) => {
                        lines.extend(pages(&alerts));
                        match renewal {
                            Renewal::Renewed { seqs: renewed, .. } => {
                                Next::Again(higher(seqs, renewed))
                            }
                            Renewal::Closed { .. } => {
                                Next::Done(Delivery::Ack, line("closed", false))
                            }
                            Renewal::Unborn => {
                                let (d, l) = unborn(heads, unit).await;
                                Next::Done(d, l)
                            }
                            Renewal::NotListed => {
                                Next::Done(Delivery::Ack, line("not_listed", false))
                            }
                            Renewal::Refused => {
                                Next::Done(Delivery::DEAD_LETTER, line("renew_refused", true))
                            }
                        }
                    }
                }
            }
            UnitRefusal::RenewNeeded(_) => {
                Next::Done(Delivery::HandBack, line("renew_needed_again", false))
            }
            UnitRefusal::SyncNeeded(seen) if !synced => {
                synced = true;
                match client.sync(seen).await {
                    Err(_) => Next::Done(Delivery::HandBack, line("sync_failed", false)),
                    Ok(Synced::Synced { seqs: synced }) => Next::Again(higher(seqs, synced)),
                    // Only the restore tool's `sync` lifts: the unit stays
                    // closed, as the `Closed` row.
                    Ok(Synced::LiftPending { .. }) => {
                        Next::Done(Delivery::Ack, line("lift_pending", false))
                    }
                    Ok(Synced::Unborn) => {
                        let (d, l) = unborn(heads, unit).await;
                        Next::Done(d, l)
                    }
                    Ok(Synced::NotListed) => Next::Done(Delivery::Ack, line("not_listed", false)),
                }
            }
            UnitRefusal::SyncNeeded(_) => {
                Next::Done(Delivery::HandBack, line("sync_needed_again", false))
            }
            UnitRefusal::Unborn => {
                let (d, l) = unborn(heads, unit).await;
                Next::Done(d, l)
            }
            UnitRefusal::AccountProblem => {
                let (d, l) = account(heads, unit).await;
                Next::Done(d, l)
            }
            UnitRefusal::Other => Next::Done(Delivery::DEAD_LETTER, line("refused", true)),
        };
        match next {
            Next::Done(delivery, last) => {
                lines.push(last);
                return (delivery, lines);
            }
            Next::Again(next) => {
                if !run.prepare(next).await {
                    lines.push(line("lease_not_given_back", false));
                    return (Delivery::HandBack, lines);
                }
                seqs = next;
            }
        }
    }
}

/// The delivery of a unit job (`renew`, `stamp_raise`): no outbox row, no
/// catalogue. Under `restore` it makes no call and is acknowledged with
/// no page (see the [module](self)). `seqs`: the message's numbers.
pub async fn deliver_unit_job<C: ConsumerClient, H: TenantHeads>(
    maintenance: Maintenance,
    job: UnitJob,
    unit: &UnitName,
    seqs: Seqs,
    client: &C,
    heads: &H,
) -> (Delivery, Vec<Line>) {
    if maintenance == Maintenance::Restore {
        return (Delivery::Ack, vec![line("maintenance", false)]);
    }
    let result = client.run_job(job, seqs).await;
    let mut lines: Vec<Line> = pages(&result.pages).collect();
    lines.push(line(result.code, false));
    let delivery = match result.delivery {
        client::Delivery::Ack => Delivery::Ack,
        client::Delivery::HandBack => Delivery::HandBack,
        client::Delivery::Unborn => {
            let (d, l) = unborn(heads, unit).await;
            lines.push(l);
            d
        }
    };
    (delivery, lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::record::{Lifecycle, TenantDoor};
    use crate::types::UnixMs;
    use crate::unit::TenantId;
    use crate::unit_router::{test_door, NoHeads};
    use std::cell::{Cell, RefCell};

    fn tenant() -> TenantId {
        TenantId::parse("t_00000000000000a7").unwrap()
    }

    fn unit() -> UnitName {
        UnitName::new(tenant(), 0)
    }

    fn seqs(state_seq: u64, keys_seq: u64) -> Seqs {
        Seqs {
            state_seq,
            keys_seq,
        }
    }

    /// A run that answers the given refusals in turn, then none; it keeps
    /// the numbers each run and each give-back carried.
    struct Script {
        answers: RefCell<Vec<Option<UnitRefusal>>>,
        carried: RefCell<Vec<Seqs>>,
        prepared: RefCell<Vec<Seqs>>,
        give_back: bool,
        finished: bool,
        outcome: JobOutcome,
    }

    impl Script {
        fn new(answers: &[Option<UnitRefusal>]) -> Script {
            Script {
                answers: RefCell::new(answers.iter().rev().copied().collect()),
                carried: RefCell::default(),
                prepared: RefCell::default(),
                give_back: true,
                finished: true,
                outcome: JobOutcome::Retry { delay_secs: 30 },
            }
        }
        fn runs(&self) -> Vec<Seqs> {
            self.carried.borrow().clone()
        }
    }

    impl UnitRun for Script {
        async fn run(&self, seqs: Seqs) -> Ran {
            self.carried.borrow_mut().push(seqs);
            let next = self.answers.borrow_mut().pop().flatten();
            Ran {
                outcome: self.outcome,
                refusal: next,
                finished: self.finished,
            }
        }
        async fn prepare(&self, seqs: Seqs) -> bool {
            self.prepared.borrow_mut().push(seqs);
            self.give_back
        }
    }

    /// The unit client: answers what it is told, counts its calls and
    /// keeps the numbers it was given.
    struct Client {
        renewal: Option<(Renewal, Vec<Page>)>,
        synced: Option<Synced>,
        job: JobResult,
        renews: Cell<u32>,
        syncs: Cell<u32>,
        jobs: Cell<u32>,
        seen: RefCell<Vec<Seqs>>,
    }

    impl Default for Client {
        fn default() -> Client {
            Client {
                renewal: Some((
                    Renewal::Renewed {
                        seqs: seqs(3, 1),
                        lease_left_ms: 600_000,
                    },
                    vec![],
                )),
                synced: Some(Synced::Synced { seqs: seqs(9, 9) }),
                job: JobResult {
                    delivery: client::Delivery::Ack,
                    code: "renewed",
                    pages: vec![],
                },
                renews: Cell::new(0),
                syncs: Cell::new(0),
                jobs: Cell::new(0),
                seen: RefCell::default(),
            }
        }
    }

    impl Client {
        fn failing() -> Client {
            Client {
                renewal: None,
                synced: None,
                ..Client::default()
            }
        }
        fn renewing(renewal: Renewal, pages: Vec<Page>) -> Client {
            Client {
                renewal: Some((renewal, pages)),
                ..Client::default()
            }
        }
        fn syncing(synced: Synced) -> Client {
            Client {
                synced: Some(synced),
                ..Client::default()
            }
        }
        fn calls(&self) -> (u32, u32, u32) {
            (self.renews.get(), self.syncs.get(), self.jobs.get())
        }
    }

    impl ConsumerClient for Client {
        async fn renew(&self, seen: Seqs) -> Result<(Renewal, Vec<Page>)> {
            self.renews.set(self.renews.get() + 1);
            self.seen.borrow_mut().push(seen);
            self.renewal.clone().ok_or(BridgeError::Sql("down".into()))
        }
        async fn sync(&self, seen: Seqs) -> Result<Synced> {
            self.syncs.set(self.syncs.get() + 1);
            self.seen.borrow_mut().push(seen);
            self.synced.clone().ok_or(BridgeError::Sql("down".into()))
        }
        async fn run_job(&self, _: UnitJob, seqs: Seqs) -> JobResult {
            self.jobs.set(self.jobs.get() + 1);
            self.seen.borrow_mut().push(seqs);
            self.job.clone()
        }
    }

    /// Tenant heads: one answer, kept, and the reads counted.
    struct Heads(Option<Option<TenantDoor>>, Cell<u32>);

    impl Heads {
        fn of(lifecycle: Lifecycle, units: &[u32]) -> Heads {
            Heads(
                Some(Some(test_door(&tenant(), 3, lifecycle, units))),
                Cell::new(0),
            )
        }
        fn none() -> Heads {
            Heads(Some(None), Cell::new(0))
        }
        fn failing() -> Heads {
            Heads(None, Cell::new(0))
        }
    }

    impl TenantHeads for Heads {
        async fn head(
            &self,
            _: &TenantId,
            known: u64,
        ) -> std::result::Result<Option<TenantDoor>, crate::directory::chain::ChainError> {
            assert_eq!(known, 0, "the chain is listed from its start");
            self.1.set(self.1.get() + 1);
            self.0
                .clone()
                .ok_or(crate::directory::chain::ChainError::Busy)
        }
    }

    async fn go(script: &Script, client: &Client, heads: &Heads) -> (Delivery, Vec<Line>) {
        deliver(Maintenance::Off, &unit(), seqs(3, 1), script, client, heads).await
    }

    fn codes(lines: &[Line]) -> Vec<(&'static str, bool)> {
        lines.iter().map(|l| (l.code, l.alert)).collect()
    }

    #[tokio::test]
    async fn no_refusal_keeps_the_jobs_outcome() {
        let s = Script::new(&[None]);
        let (d, l) = go(&s, &Client::default(), &Heads::failing()).await;
        assert_eq!(d, Delivery::Retry { delay_secs: 30 });
        assert!(l.is_empty());
        assert_eq!(s.runs(), [seqs(3, 1)]);
        assert!(s.prepared.borrow().is_empty());
    }

    #[tokio::test]
    async fn stale_runs_once_more_with_the_units_numbers_then_acknowledges() {
        let s = Script::new(&[Some(UnitRefusal::Stale(seqs(5, 2))), None]);
        let (d, l) = go(&s, &Client::default(), &Heads::failing()).await;
        assert_eq!((d, l), (Delivery::Retry { delay_secs: 30 }, vec![]));
        assert_eq!(s.runs(), [seqs(3, 1), seqs(5, 2)]);
        assert_eq!(*s.prepared.borrow(), [seqs(5, 2)]);

        let s = Script::new(&[
            Some(UnitRefusal::Stale(seqs(5, 2))),
            Some(UnitRefusal::Stale(seqs(6, 2))),
        ]);
        let (d, l) = go(&s, &Client::default(), &Heads::failing()).await;
        assert_eq!(d, Delivery::Ack);
        assert_eq!(codes(&l), [("stale_again", false)]);
        assert_eq!(s.runs().len(), 2);
    }

    /// The lease of the first run is given back before the run once more;
    /// if it cannot be, the message is handed back (review of L6-1, MEDIUM).
    #[tokio::test]
    async fn a_lease_not_given_back_hands_the_message_back() {
        let mut s = Script::new(&[Some(UnitRefusal::Stale(seqs(5, 2))), None]);
        s.give_back = false;
        let (d, l) = go(&s, &Client::default(), &Heads::failing()).await;
        assert_eq!(d, Delivery::HandBack);
        assert_eq!(codes(&l), [("lease_not_given_back", false)]);
        assert_eq!(s.runs().len(), 1);
    }

    #[tokio::test]
    async fn a_job_without_numbers_pages() {
        let s = Script::new(&[Some(UnitRefusal::StaleJob)]);
        let (d, l) = go(&s, &Client::default(), &Heads::failing()).await;
        assert_eq!(d, Delivery::DEAD_LETTER);
        assert_eq!(codes(&l), [("stale_job_no_numbers", true)]);
        assert_eq!(s.runs().len(), 1);
    }

    #[tokio::test]
    async fn closed_is_acknowledged() {
        let s = Script::new(&[Some(UnitRefusal::Closed)]);
        let (d, l) = go(&s, &Client::default(), &Heads::failing()).await;
        assert_eq!(d, Delivery::Ack);
        assert_eq!(codes(&l), [("closed", false)]);
    }

    #[tokio::test]
    async fn renew_needed_renews_then_runs_once_more() {
        let c = Client::default();
        let s = Script::new(&[Some(UnitRefusal::RenewNeeded(seqs(3, 1))), None]);
        let (d, l) = go(&s, &c, &Heads::failing()).await;
        assert_eq!((d, l), (Delivery::Retry { delay_secs: 30 }, vec![]));
        assert_eq!(c.calls(), (1, 0, 0));
        assert_eq!(*c.seen.borrow(), [seqs(3, 1)]);
        assert_eq!(s.runs(), [seqs(3, 1), seqs(3, 1)]);
        // Renewed, and refused again: handed back, not renewed twice.
        let c = Client::default();
        let s = Script::new(&[
            Some(UnitRefusal::RenewNeeded(seqs(3, 1))),
            Some(UnitRefusal::RenewNeeded(seqs(3, 1))),
        ]);
        let (d, l) = go(&s, &c, &Heads::failing()).await;
        assert_eq!(d, Delivery::HandBack);
        assert_eq!(codes(&l), [("renew_needed_again", false)]);
        assert_eq!(c.calls(), (1, 0, 0));
        // A failed renewal hands back with the queue's delay.
        let s = Script::new(&[Some(UnitRefusal::RenewNeeded(seqs(3, 1)))]);
        let (d, l) = go(&s, &Client::failing(), &Heads::failing()).await;
        assert_eq!(d, Delivery::HandBack);
        assert_eq!(codes(&l), [("renew_failed", false)]);
        assert_eq!(s.runs().len(), 1);
    }

    /// What a renewal comes to besides `Renewed` takes the table's rows;
    /// its pages are alerts.
    #[tokio::test]
    async fn the_renewals_outcomes_take_the_tables_rows() {
        let refused = || Script::new(&[Some(UnitRefusal::RenewNeeded(seqs(3, 1)))]);
        let cases = [
            (
                Renewal::Closed { rolled_back: true },
                vec![Page::RolledBack],
                Heads::failing(),
                Delivery::Ack,
                vec![("rolled_back", true), ("closed", false)],
            ),
            (
                Renewal::Unborn,
                vec![],
                Heads::of(Lifecycle::Live, &[0]),
                Delivery::DEAD_LETTER,
                vec![("catalogue_lost", true)],
            ),
            (
                Renewal::Unborn,
                vec![],
                Heads::of(Lifecycle::Live, &[1]),
                Delivery::Ack,
                vec![("unborn_unlisted", false)],
            ),
            (
                Renewal::NotListed,
                vec![],
                Heads::failing(),
                Delivery::Ack,
                vec![("not_listed", false)],
            ),
            (
                Renewal::Refused,
                vec![Page::FinisherNotTold],
                Heads::failing(),
                Delivery::DEAD_LETTER,
                vec![("finisher_not_told", true), ("renew_refused", true)],
            ),
        ];
        for (renewal, pages, heads, want, lines) in cases {
            let s = refused();
            let c = Client::renewing(renewal.clone(), pages);
            let (d, l) = go(&s, &c, &heads).await;
            assert_eq!(d, want, "{renewal:?}");
            assert_eq!(codes(&l), lines, "{renewal:?}");
            assert_eq!(s.runs().len(), 1, "{renewal:?}");
        }
    }

    #[tokio::test]
    async fn sync_needed_syncs_then_runs_once_more_never_below_the_message() {
        let c = Client::syncing(Synced::Synced { seqs: seqs(7, 4) });
        let s = Script::new(&[Some(UnitRefusal::SyncNeeded(seqs(2, 1))), None]);
        let (d, l) = go(&s, &c, &Heads::failing()).await;
        assert_eq!((d, l), (Delivery::Retry { delay_secs: 30 }, vec![]));
        assert_eq!(c.calls(), (0, 1, 0));
        assert_eq!(*c.seen.borrow(), [seqs(2, 1)]);
        assert_eq!(s.runs(), [seqs(3, 1), seqs(7, 4)]);
        // A synced head below the message's numbers: the run once more
        // keeps the message's, so the unit refuses it again and it is
        // handed back (review of L6-1, LOW).
        let c = Client::syncing(Synced::Synced { seqs: seqs(2, 1) });
        let s = Script::new(&[
            Some(UnitRefusal::SyncNeeded(seqs(2, 1))),
            Some(UnitRefusal::SyncNeeded(seqs(2, 1))),
        ]);
        let (d, l) = go(&s, &c, &Heads::failing()).await;
        assert_eq!(s.runs(), [seqs(3, 1), seqs(3, 1)]);
        assert_eq!(d, Delivery::HandBack);
        assert_eq!(codes(&l), [("sync_needed_again", false)]);
        let s = Script::new(&[Some(UnitRefusal::SyncNeeded(seqs(2, 1)))]);
        let (d, l) = go(&s, &Client::failing(), &Heads::failing()).await;
        assert_eq!(d, Delivery::HandBack);
        assert_eq!(codes(&l), [("sync_failed", false)]);
    }

    #[tokio::test]
    async fn the_syncs_outcomes_take_the_tables_rows() {
        for (synced, heads, want, code) in [
            (
                Synced::LiftPending { seqs: seqs(3, 1) },
                Heads::failing(),
                Delivery::Ack,
                ("lift_pending", false),
            ),
            (
                Synced::Unborn,
                Heads::of(Lifecycle::Live, &[0]),
                Delivery::DEAD_LETTER,
                ("catalogue_lost", true),
            ),
            (
                Synced::Unborn,
                Heads::failing(),
                Delivery::HandBack,
                ("unborn_head_unread", false),
            ),
            (
                Synced::NotListed,
                Heads::failing(),
                Delivery::Ack,
                ("not_listed", false),
            ),
        ] {
            let s = Script::new(&[Some(UnitRefusal::SyncNeeded(seqs(2, 1)))]);
            let (d, l) = go(&s, &Client::syncing(synced.clone()), &heads).await;
            assert_eq!(d, want, "{synced:?}");
            assert_eq!(codes(&l), [code], "{synced:?}");
        }
    }

    /// Each fix once per delivery (confirmation review of L6-1, MEDIUM):
    /// the unit's numbers, then a renewal, then a third run.
    #[tokio::test]
    async fn each_fix_runs_once_per_delivery() {
        let c = Client::default();
        let s = Script::new(&[
            Some(UnitRefusal::Stale(seqs(5, 2))),
            Some(UnitRefusal::RenewNeeded(seqs(5, 2))),
            None,
        ]);
        let (d, l) = go(&s, &c, &Heads::failing()).await;
        assert_eq!((d, l), (Delivery::Retry { delay_secs: 30 }, vec![]));
        assert_eq!(c.calls(), (1, 0, 0));
        assert_eq!(s.runs().len(), 3);
        assert_eq!(s.prepared.borrow().len(), 2);
        // All three fixes, then the same refusal again.
        let c = Client::syncing(Synced::Synced { seqs: seqs(6, 2) });
        let s = Script::new(&[
            Some(UnitRefusal::Stale(seqs(5, 2))),
            Some(UnitRefusal::RenewNeeded(seqs(5, 2))),
            Some(UnitRefusal::SyncNeeded(seqs(5, 2))),
            Some(UnitRefusal::RenewNeeded(seqs(6, 2))),
        ]);
        let (d, l) = go(&s, &c, &Heads::failing()).await;
        assert_eq!(d, Delivery::HandBack);
        assert_eq!(codes(&l), [("renew_needed_again", false)]);
        assert_eq!(c.calls(), (1, 1, 0));
        assert_eq!(s.runs().len(), 4);
        // A shred found after two fixes: acknowledged, no page.
        let s = Script::new(&[
            Some(UnitRefusal::Stale(seqs(5, 2))),
            Some(UnitRefusal::RenewNeeded(seqs(5, 2))),
            Some(UnitRefusal::AccountProblem),
        ]);
        let heads = Heads::of(Lifecycle::Shredding, &[0]);
        let (d, l) = go(&s, &Client::default(), &heads).await;
        assert_eq!(d, Delivery::Ack);
        assert_eq!(codes(&l), [("shredding", false)]);
    }

    /// A run the job table gave up never runs once more (confirmation
    /// review of L6-1, LOW): the table's retry stands.
    #[tokio::test]
    async fn a_run_given_up_by_the_job_table_is_not_run_once_more() {
        let mut s = Script::new(&[Some(UnitRefusal::RenewNeeded(seqs(3, 1)))]);
        s.finished = false;
        let c = Client::default();
        let (d, l) = go(&s, &c, &Heads::failing()).await;
        assert_eq!(d, Delivery::Retry { delay_secs: 30 });
        assert_eq!(codes(&l), [("job_not_finished", false)]);
        assert_eq!(s.runs().len(), 1);
        assert!(s.prepared.borrow().is_empty());
        assert_eq!(c.calls(), (0, 0, 0));
    }

    #[tokio::test]
    async fn unborn_is_decided_by_the_verified_head() {
        for (heads, want, code) in [
            (
                Heads::of(Lifecycle::Live, &[0]),
                Delivery::DEAD_LETTER,
                ("catalogue_lost", true),
            ),
            (
                Heads::of(Lifecycle::Live, &[1]),
                Delivery::Ack,
                ("unborn_unlisted", false),
            ),
            // No chain: no record lists the unit.
            (Heads::none(), Delivery::Ack, ("unborn_unlisted", false)),
            // Never acknowledged on a head it could not read.
            (
                Heads::failing(),
                Delivery::HandBack,
                ("unborn_head_unread", false),
            ),
        ] {
            let s = Script::new(&[Some(UnitRefusal::Unborn)]);
            let (d, l) = go(&s, &Client::default(), &heads).await;
            assert_eq!((d, codes(&l)), (want, vec![code]));
            assert_eq!(heads.1.get(), 1);
        }
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
        for lifecycle in [Lifecycle::Shredding, Lifecycle::Shredded] {
            let s = Script::new(&[Some(UnitRefusal::AccountProblem)]);
            let (d, l) = go(&s, &Client::default(), &Heads::of(lifecycle, &[])).await;
            assert_eq!(d, Delivery::Ack, "{lifecycle:?}");
            assert_eq!(codes(&l), [("shredding", false)]);
        }
        let s = Script::new(&[Some(UnitRefusal::AccountProblem)]);
        let (d, l) = go(&s, &Client::default(), &Heads::of(Lifecycle::Live, &[0])).await;
        assert_eq!(d, Delivery::DEAD_LETTER);
        assert_eq!(codes(&l), [("account_problem", true)]);
        let s = Script::new(&[Some(UnitRefusal::AccountProblem)]);
        let (d, l) = go(&s, &Client::default(), &Heads::failing()).await;
        assert_eq!(d, Delivery::HandBack);
        assert_eq!(codes(&l), [("account_head_unread", false)]);
    }

    #[tokio::test]
    async fn any_other_refusal_pages() {
        let s = Script::new(&[Some(UnitRefusal::Other)]);
        let (d, l) = go(&s, &Client::default(), &Heads::failing()).await;
        assert_eq!(d, Delivery::DEAD_LETTER);
        assert_eq!(codes(&l), [("refused", true)]);
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
        assert_eq!(codes(&l), [("maintenance", false)]);
        assert!(s.runs().is_empty());
        for job in [
            UnitJob::Renew { at: UnixMs(1) },
            UnitJob::StampRaise { at: UnixMs(1) },
        ] {
            let (d, l) =
                deliver_unit_job(Maintenance::Restore, job, &unit(), seqs(3, 1), &c, &h).await;
            assert_eq!(d, Delivery::Ack);
            assert_eq!(codes(&l), [("maintenance", false)]);
        }
        assert_eq!(c.calls(), (0, 0, 0));
        assert_eq!(h.1.get(), 0);
    }

    #[tokio::test]
    async fn unit_jobs_run_through_the_client_with_the_messages_numbers() {
        let c = Client::default();
        let h = Heads::failing();
        let job = UnitJob::Renew { at: UnixMs(1) };
        let (d, l) = deliver_unit_job(Maintenance::Off, job, &unit(), seqs(4, 2), &c, &h).await;
        assert_eq!((d, codes(&l)), (Delivery::Ack, vec![("renewed", false)]));
        assert_eq!(*c.seen.borrow(), [seqs(4, 2)]);
        // Hand back, and an unborn unit decided by the head, with pages.
        let c = Client {
            job: JobResult {
                delivery: client::Delivery::HandBack,
                code: "renew_failed",
                pages: vec![Page::RevocationsShort { listed: 1, held: 2 }],
            },
            ..Client::default()
        };
        let (d, l) = deliver_unit_job(Maintenance::Off, job, &unit(), seqs(4, 2), &c, &h).await;
        assert_eq!(d, Delivery::HandBack);
        assert_eq!(
            codes(&l),
            [("revocations_short", true), ("renew_failed", false)]
        );
        for (heads, want, code) in [
            (
                Heads::of(Lifecycle::Live, &[0]),
                Delivery::DEAD_LETTER,
                ("catalogue_lost", true),
            ),
            (
                Heads::of(Lifecycle::Live, &[]),
                Delivery::Ack,
                ("unborn_unlisted", false),
            ),
        ] {
            let c = Client {
                job: JobResult {
                    delivery: client::Delivery::Unborn,
                    code: "unborn",
                    pages: vec![],
                },
                ..Client::default()
            };
            let (d, l) =
                deliver_unit_job(Maintenance::Off, job, &unit(), seqs(4, 2), &c, &heads).await;
            assert_eq!(d, want);
            assert_eq!(codes(&l), [("unborn", false), code]);
        }
        // This build has no client: handed back.
        let (d, l) =
            deliver_unit_job(Maintenance::Off, job, &unit(), seqs(4, 2), &NoClient, &h).await;
        assert_eq!(d, Delivery::HandBack);
        assert_eq!(codes(&l), [("no_unit_client", false)]);
    }

    #[test]
    fn page_codes_are_fixed_and_distinct() {
        let all = [
            Page::StrayRevocationNames(vec!["x".into()]),
            Page::RevocationsShort { listed: 0, held: 1 },
            Page::RolledBack,
            Page::RenewRefused(crate::unit_lease::lease::LeaseRefusal::NoLeaseTable),
            Page::FinisherNotTold,
        ];
        let codes: std::collections::BTreeSet<_> = all.iter().map(page_code).collect();
        assert_eq!(codes.len(), all.len());
    }
}
