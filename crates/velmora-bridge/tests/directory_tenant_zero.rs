//! The fence on tenant 0's D1 catalogue: the selector read from tenant 0's
//! record, the cutover marker and the catalogue id of the database, what
//! an isolate has seen, and the route of a request when the directory
//! read fails.

use std::cell::Cell;

use velmora_bridge::directory::chain::{record_key, TenantChain, Written};
use velmora_bridge::directory::record::{TenantDoor, TenantId};
use velmora_bridge::directory::tenant_zero::{
    database_facts, decide, route_without_directory, DatabaseFacts, DirectoryAnswer, Lookup, Route,
    Seen, ZeroServe, ZeroWatch, CUTOVER_MARKER_KEY, RECHECK_MS,
};
use velmora_bridge::directory::testing::{MemRecords, PlainSeal};
use velmora_bridge::directory::transition::{Actor, Change, RETIRE_AFTER_MS};
use velmora_bridge::testkit::RusqliteSql;
use velmora_bridge::{Sql, SqlValue, UnixMs};

const NOW: UnixMs = UnixMs(1_800_000_000_000);

type Chain<'a> = TenantChain<'a, MemRecords, PlainSeal>;

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

fn t1() -> TenantId {
    TenantId::parse("t_00000000000000a1").unwrap()
}

/// Writes one change to tenant 0's chain and answers the new head.
fn write(chain: &Chain<'_>, change: Change, actor: Actor, now: UnixMs) -> TenantDoor {
    let w = block_on(chain.write(&TenantId::zero(), &change, actor, now, 0)).unwrap();
    let Written::Wrote(rec) = w else {
        panic!("{change:?}: {w:?}")
    };
    rec.door
}

fn first(chain: &Chain<'_>) -> TenantDoor {
    write(
        chain,
        Change::CreateTenantZero {
            jurisdiction: "us".into(),
        },
        Actor::Operator,
        NOW,
    )
}

fn start(chain: &Chain<'_>, frozen: &str) -> TenantDoor {
    write(
        chain,
        Change::StartMove {
            to: t1(),
            catalogue_id_frozen: frozen.into(),
        },
        Actor::MoveTool,
        NOW,
    )
}

fn flip(chain: &Chain<'_>, stamp: u64) -> TenantDoor {
    write(chain, Change::FlipMove { stamp }, Actor::MoveTool, NOW)
}

fn undo(chain: &Chain<'_>, stamp: u64, id: &str) -> TenantDoor {
    write(
        chain,
        Change::UndoMove {
            undo_stamp: stamp,
            catalogue_id: id.into(),
        },
        Actor::MoveTool,
        NOW,
    )
}

/// A database; `marker` is the first move's marker.
fn db(marker: bool, id: Option<&str>) -> DatabaseFacts {
    db_marked(marker.then_some(1), id)
}

fn db_marked(marker: Option<i64>, id: Option<&str>) -> DatabaseFacts {
    DatabaseFacts {
        marker,
        catalogue_id: id.map(str::to_string),
    }
}

fn paged(code: &'static str) -> ZeroServe {
    ZeroServe::Unavailable { code, page: true }
}

fn fresh() -> Seen {
    Seen::default()
}

#[test]
fn the_selector_the_marker_and_the_catalogue_id_decide() {
    let store = MemRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let main = db(false, Some("main"));
    let base = first(&chain);
    // Today.
    assert_eq!(decide(&base, &main, &mut fresh()), ZeroServe::Serve);
    // The marker is written before the window's record: reads only.
    assert_eq!(
        decide(&base, &db(true, Some("main")), &mut fresh()),
        ZeroServe::ServeReadOnly
    );
    // The window: reads only, and only from the frozen catalogue.
    let moving = start(&chain, "main");
    assert_eq!(
        decide(&moving, &db(true, Some("main")), &mut fresh()),
        ZeroServe::ServeReadOnly
    );
    for other in [db(true, Some("main2")), db(true, None)] {
        assert_eq!(
            decide(&moving, &other, &mut fresh()),
            paged("database_is_not_the_frozen_one")
        );
    }
    // After the flip: moved, whatever the database says.
    let moved = flip(&chain, 9);
    for facts in [db(false, None), db(true, Some("main"))] {
        assert_eq!(decide(&moved, &facts, &mut fresh()), ZeroServe::Moved);
    }
    // The undo serves only the catalogue it names.
    let undone = undo(&chain, 10, "main2");
    assert_eq!(
        decide(&undone, &db(false, Some("main2")), &mut fresh()),
        ZeroServe::Serve
    );
    for facts in [
        db(false, Some("main")),
        db(true, Some("main")),
        db(false, None),
    ] {
        assert_eq!(
            decide(&undone, &facts, &mut fresh()),
            paged("database_is_not_the_named_one")
        );
    }
    // The named database with a marker after a move: left behind.
    assert_eq!(
        decide(&undone, &db(true, Some("main2")), &mut fresh()),
        paged("database_left_behind")
    );
    // Retired 30 days after the flip of a second move, from the named
    // catalogue.
    start(&chain, "main2");
    flip(&chain, 11);
    let retired = write(
        &chain,
        Change::RetireTenantZero,
        Actor::MoveTool,
        UnixMs(NOW.0 + RETIRE_AFTER_MS),
    );
    assert_eq!(
        decide(&retired, &db(false, Some("main2")), &mut fresh()),
        paged("tenant_zero_retired")
    );
}

/// Heads that the transitions never write, as damage or a forged record
/// would leave them.
#[test]
fn heads_that_no_transition_writes_are_refused() {
    let store = MemRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let base = first(&chain);
    start(&chain, "main");
    let moved = flip(&chain, 9);
    let main = db(false, Some("main"));

    // d1 with the move and no undo above its stamp: left behind.
    let mut left = moved.clone();
    left.tenant_zero.as_mut().unwrap().selector = velmora_bridge::directory::record::Selector::D1;
    assert_eq!(
        decide(&left, &main, &mut fresh()),
        paged("database_left_behind")
    );
    // An undo stamp with no move.
    let mut stray = base.clone();
    stray.tenant_zero.as_mut().unwrap().undo_stamp = Some(3);
    assert_eq!(
        decide(&stray, &main, &mut fresh()),
        paged("undo_without_move")
    );
    // Not tenant 0's record, or no selector.
    let mut other = base.clone();
    other.tenant = t1();
    assert_eq!(
        decide(&other, &main, &mut fresh()),
        paged("not_tenant_zero")
    );
    let mut none = base.clone();
    none.tenant_zero = None;
    assert_eq!(
        decide(&none, &main, &mut fresh()),
        paged("selector_missing")
    );
}

/// An isolate that has met `moved` serves d1 afterwards only from the
/// catalogue that an undo named.
#[test]
fn moved_stays_seen() {
    let store = MemRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let base = first(&chain);
    start(&chain, "main");
    let moved = flip(&chain, 9);
    let mut seen = fresh();
    assert_eq!(
        decide(&moved, &db(false, Some("main")), &mut seen),
        ZeroServe::Moved
    );
    assert!(seen.moved);
    // The first record again (a rolled-back view): refused.
    assert_eq!(
        decide(&base, &db(false, Some("main")), &mut seen),
        paged("selector_went_back")
    );
    // After the undo, the named catalogue only, and seen stays.
    let undone = undo(&chain, 10, "main2");
    assert_eq!(
        decide(&undone, &db(false, Some("main2")), &mut seen),
        ZeroServe::Serve
    );
    assert!(seen.moved);
    assert_eq!(
        decide(&base, &db(false, Some("main2")), &mut seen),
        paged("selector_went_back")
    );
    // A second window and its give-up keep the named catalogue.
    let moving = start(&chain, "main2");
    assert_eq!(
        decide(&moving, &db(true, Some("main2")), &mut seen),
        ZeroServe::ServeReadOnly
    );
    let given_up = write(&chain, Change::GiveUpMove, Actor::MoveTool, NOW);
    assert_eq!(
        decide(&given_up, &db(false, Some("main2")), &mut seen),
        ZeroServe::Serve
    );
    assert_eq!(
        decide(&given_up, &db(false, Some("main")), &mut seen),
        paged("database_is_not_the_named_one")
    );
}

/// The isolate reads tenant 0's head once, checks it every RECHECK_MS by
/// one listing, whatever it says, and reads it again when it moved.
#[test]
fn the_watch_rechecks_the_head_and_follows_the_move() {
    let store = MemRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    first(&chain);
    let main = db(false, Some("main"));
    let mut watch = ZeroWatch::default();
    block_on(async {
        assert_eq!(watch.serve(&chain, &main, NOW).await, ZeroServe::Serve);
    });
    start(&chain, "main");
    flip(&chain, 9);
    block_on(async {
        // Inside the interval the cached head stands, with no listing.
        let lists = store.lists();
        let soon = UnixMs(NOW.0 + RECHECK_MS - 1);
        assert_eq!(watch.serve(&chain, &main, soon).await, ZeroServe::Serve);
        assert_eq!(store.lists(), lists);
        // After it, the head is checked and read again.
        let later = UnixMs(NOW.0 + RECHECK_MS);
        assert_eq!(watch.serve(&chain, &main, later).await, ZeroServe::Moved);
        assert_eq!(store.lists(), lists + 1);
        // A moved head is checked on the same interval.
        let lists = store.lists();
        let t = UnixMs(later.0 + 1);
        assert_eq!(watch.serve(&chain, &main, t).await, ZeroServe::Moved);
        assert_eq!(store.lists(), lists);
    });
    undo(&chain, 10, "main2");
    block_on(async {
        let t = UnixMs(NOW.0 + 2 * RECHECK_MS);
        assert_eq!(
            watch.serve(&chain, &db(false, Some("main2")), t).await,
            ZeroServe::Serve
        );
        // A clock that goes back does not keep a stale head.
        let lists = store.lists();
        watch.serve(&chain, &db(false, Some("main2")), NOW).await;
        assert_eq!(store.lists(), lists + 1);
    });
}

#[test]
fn a_record_that_cannot_be_read_answers_503() {
    let store = MemRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let main = db(false, Some("main"));
    // No record at all: damage, paged.
    let mut watch = ZeroWatch::default();
    assert_eq!(
        block_on(watch.serve(&chain, &main, NOW)),
        paged("record_damaged")
    );
    first(&chain);
    let mut watch = ZeroWatch::default();
    assert_eq!(block_on(watch.serve(&chain, &main, NOW)), ZeroServe::Serve);
    // R2 fails at the next check: 503, an outage and not damage.
    store.fail_lists(true);
    let t = UnixMs(NOW.0 + RECHECK_MS);
    assert_eq!(
        block_on(watch.serve(&chain, &main, t)),
        ZeroServe::Unavailable {
            code: "record_unreadable",
            page: false
        }
    );
    // A record changed behind the chain's back: damage.
    store.fail_lists(false);
    let key = record_key(&TenantId::zero(), 1);
    let mut bytes = store.raw(&key).unwrap();
    bytes[0] ^= 1;
    store.plant(&key, bytes);
    let mut watch = ZeroWatch::default();
    assert_eq!(
        block_on(watch.serve(&chain, &main, NOW)),
        paged("record_damaged")
    );
}

#[test]
fn the_database_says_whether_it_carries_the_marker_and_which_id() {
    let catalog = RusqliteSql::with_schema().unwrap();
    block_on(async {
        assert_eq!(database_facts(&catalog).await.unwrap(), db(false, None));
        catalog
            .exec(
                "INSERT INTO rollback_stamp (id, counter, catalogue_id) VALUES (1, 3, 'main')",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(
            database_facts(&catalog).await.unwrap(),
            db(false, Some("main"))
        );
        catalog
            .exec(
                "INSERT INTO meta (k, v) VALUES (?1, ?2)",
                &[
                    SqlValue::Text(CUTOVER_MARKER_KEY.into()),
                    SqlValue::Int(NOW.0),
                ],
            )
            .await
            .unwrap();
        assert_eq!(
            database_facts(&catalog).await.unwrap(),
            db_marked(Some(NOW.0), Some("main"))
        );
    });
}

/// Calls of the two lookups, so that a test can say which ran.
#[derive(Default)]
struct Asked {
    record: Cell<u32>,
    zero: Cell<u32>,
}

fn route(
    asked: &Asked,
    answer: DirectoryAnswer,
    zero: ZeroServe,
    record: Lookup<TenantId>,
    held: Lookup<()>,
) -> Route {
    block_on(route_without_directory(
        answer,
        zero,
        async || {
            asked.record.set(asked.record.get() + 1);
            record
        },
        async || {
            asked.zero.set(asked.zero.get() + 1);
            held
        },
    ))
}

#[test]
fn a_failed_directory_read_is_not_an_unknown_key() {
    let moved = ZeroServe::Moved;
    let serve = ZeroServe::Serve;
    // A directory that was read decides, and nothing else is asked.
    let a = Asked::default();
    let r = route(
        &a,
        DirectoryAnswer::Read(Some(t1())),
        serve,
        Lookup::Failed,
        Lookup::Failed,
    );
    assert_eq!(r, Route::Tenant(t1()));
    let r = route(
        &a,
        DirectoryAnswer::Read(None),
        serve,
        Lookup::Failed,
        Lookup::Failed,
    );
    assert_eq!(r, Route::UnknownKey);
    assert_eq!((a.record.get(), a.zero.get()), (0, 0));

    // A failed read: the route record first.
    let a = Asked::default();
    let r = route(
        &a,
        DirectoryAnswer::Failed,
        serve,
        Lookup::Found(t1()),
        Lookup::Found(()),
    );
    assert_eq!(r, Route::Tenant(t1()));
    assert_eq!((a.record.get(), a.zero.get()), (1, 0));
    // A route record that cannot be read: 503, tenant 0 is not asked.
    let a = Asked::default();
    let r = route(
        &a,
        DirectoryAnswer::Failed,
        serve,
        Lookup::Failed,
        Lookup::Found(()),
    );
    assert_eq!(r, Route::Unavailable);
    assert_eq!(a.zero.get(), 0);

    // No route record, tenant 0 on D1: its catalogue decides.
    for zero in [ZeroServe::Serve, ZeroServe::ServeReadOnly] {
        let a = Asked::default();
        let r = route(
            &a,
            DirectoryAnswer::Failed,
            zero,
            Lookup::Absent,
            Lookup::Found(()),
        );
        assert_eq!(r, Route::Tenant(TenantId::zero()));
        // Not held, or the lookup failed: 503, never another tenant.
        for held in [Lookup::Absent, Lookup::Failed] {
            let r = route(&a, DirectoryAnswer::Failed, zero, Lookup::Absent, held);
            assert_eq!(r, Route::Unavailable);
        }
    }
    // After the move tenant 0's catalogue is not asked at all.
    let a = Asked::default();
    let r = route(
        &a,
        DirectoryAnswer::Failed,
        moved,
        Lookup::Absent,
        Lookup::Found(()),
    );
    assert_eq!(r, Route::Unavailable);
    assert_eq!(a.zero.get(), 0);
    let r = route(
        &a,
        DirectoryAnswer::Failed,
        paged("database_left_behind"),
        Lookup::Absent,
        Lookup::Found(()),
    );
    assert_eq!(r, Route::Unavailable);
    assert_eq!(a.zero.get(), 0);
}

/// The fallback undo lands on the frozen catalogue once it is thawed: its
/// marker gone, it serves; with the marker still there it does not.
#[test]
fn the_fallback_undo_serves_the_thawed_frozen_catalogue() {
    let store = MemRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    first(&chain);
    start(&chain, "main");
    flip(&chain, 9);
    let back = write(
        &chain,
        Change::UndoMoveOntoFrozen {
            undo_stamp: 10,
            levelled_to: 9,
        },
        Actor::MoveTool,
        NOW,
    );
    let mut seen = Seen { moved: true };
    assert_eq!(
        decide(&back, &db(false, Some("main")), &mut seen),
        ZeroServe::Serve
    );
    assert_eq!(
        decide(&back, &db(true, Some("main")), &mut seen),
        paged("database_left_behind")
    );
}

/// After an undo, the next move writes its marker into the catalogue the
/// undo named before its window's record: reads go on there. A marker of
/// the move already made is a database left behind.
#[test]
fn the_next_moves_marker_opens_a_window_and_an_old_one_is_left_behind() {
    let store = MemRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    first(&chain);
    start(&chain, "main");
    flip(&chain, 9);
    let undone = undo(&chain, 10, "main2");
    let mut seen = Seen { moved: true };
    assert_eq!(
        decide(&undone, &db_marked(Some(2), Some("main2")), &mut seen),
        ZeroServe::ServeReadOnly
    );
    assert_eq!(
        decide(&undone, &db_marked(Some(1), Some("main2")), &mut seen),
        paged("database_left_behind")
    );
    // The give-up of that window before its record: unchanged, and the
    // thawed catalogue serves again.
    let w = block_on(chain.write(
        &TenantId::zero(),
        &Change::GiveUpMove,
        Actor::MoveTool,
        NOW,
        0,
    ))
    .unwrap();
    assert!(matches!(w, Written::Unchanged(_)));
    assert_eq!(
        decide(&undone, &db(false, Some("main2")), &mut seen),
        ZeroServe::Serve
    );
}

/// An isolate that cached the d1 head before the window serves reads only
/// once the database carries the marker, inside the interval too.
#[test]
fn a_cached_d1_head_meets_the_marker() {
    let store = MemRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    first(&chain);
    let mut watch = ZeroWatch::default();
    assert_eq!(
        block_on(watch.serve(&chain, &db(false, Some("main")), NOW)),
        ZeroServe::Serve
    );
    let soon = UnixMs(NOW.0 + 1);
    assert_eq!(
        block_on(watch.serve(&chain, &db(true, Some("main")), soon)),
        ZeroServe::ServeReadOnly
    );
}

/// A second window that was given up leaves its marker until the thaw:
/// reads only, never a page.
#[test]
fn a_given_up_second_window_serves_reads_until_the_thaw() {
    let store = MemRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    first(&chain);
    start(&chain, "main");
    flip(&chain, 9);
    undo(&chain, 10, "main2");
    start(&chain, "main2");
    let given_up = write(&chain, Change::GiveUpMove, Actor::MoveTool, NOW);
    let mut seen = Seen { moved: true };
    assert_eq!(
        decide(&given_up, &db_marked(Some(2), Some("main2")), &mut seen),
        ZeroServe::ServeReadOnly
    );
    assert_eq!(
        decide(&given_up, &db_marked(Some(1), Some("main2")), &mut seen),
        paged("database_left_behind")
    );
}

/// The first window given up after its record: the record goes back to
/// d1 before the marker is cleared, and in between reads are served.
#[test]
fn a_first_window_given_up_serves_reads_until_the_thaw() {
    let store = MemRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    first(&chain);
    start(&chain, "main");
    let back = write(&chain, Change::GiveUpMove, Actor::MoveTool, NOW);
    assert_eq!(
        decide(&back, &db(true, Some("main")), &mut fresh()),
        ZeroServe::ServeReadOnly
    );
    assert_eq!(
        decide(&back, &db(false, Some("main")), &mut fresh()),
        ZeroServe::Serve
    );
}
