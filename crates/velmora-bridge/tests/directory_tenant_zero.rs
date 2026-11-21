//! The fence on tenant 0's D1 catalogue: the selector read from tenant 0's
//! record, the cutover marker of the database, `moved` sticky until a
//! stamped undo, and the route of a request when the directory fails.

use std::cell::Cell;

use velmora_bridge::directory::chain::{record_key, ControlSeal, TenantChain, Written};
use velmora_bridge::directory::record::{Selector, TenantDoor, TenantId, TenantZero};
use velmora_bridge::directory::tenant_zero::{
    database_facts, decide, route_without_directory, DatabaseFacts, DirectoryAnswer, Route, Seen,
    ZeroServe, ZeroWatch, CUTOVER_MARKER_KEY, RECHECK_MS,
};
use velmora_bridge::directory::testing::{MemRecords, PlainSeal};
use velmora_bridge::directory::transition::{Actor, Change};
use velmora_bridge::testkit::RusqliteSql;
use velmora_bridge::{Sql, SqlValue, UnixMs};

const NOW: UnixMs = UnixMs(1_800_000_000_000);

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

fn t1() -> TenantId {
    TenantId::parse("t_00000000000000a1").unwrap()
}

/// Tenant 0's first record, as the chain writes it.
fn first_record(chain: &TenantChain<'_, MemRecords, PlainSeal>) -> TenantDoor {
    let w = block_on(chain.write(
        &TenantId::zero(),
        &Change::CreateTenantZero {
            jurisdiction: "us".into(),
        },
        Actor::Operator,
        NOW,
        0,
    ))
    .unwrap();
    let Written::Wrote(rec) = w else {
        panic!("{w:?}")
    };
    rec.door
}

/// A later record of tenant 0, put by hand as the move's own tool would.
fn plant(store: &MemRecords, seal: &PlainSeal, prev: &TenantDoor, zero: TenantZero) -> TenantDoor {
    let mut door = prev.clone();
    door.seq += 1;
    door.tenant_zero = Some(zero);
    let name = record_key(&TenantId::zero(), door.seq);
    let sealed = seal
        .seal(
            &name,
            &TenantId::zero(),
            0,
            &serde_json::to_vec(&door).unwrap(),
            b"{\"v\":1}",
        )
        .unwrap();
    store.plant(&name, sealed);
    door
}

fn zero(selector: Selector, cut: Option<u64>, undo: Option<u64>, id: Option<&str>) -> TenantZero {
    TenantZero {
        selector,
        cutover_stamp: cut,
        undo_stamp: undo,
        catalogue_id: id.map(str::to_string),
    }
}

fn moved() -> Selector {
    Selector::Moved { to: t1() }
}

fn with(door: &TenantDoor, z: TenantZero) -> TenantDoor {
    let mut d = door.clone();
    d.tenant_zero = Some(z);
    d
}

fn db(marker: bool, id: Option<&str>) -> DatabaseFacts {
    DatabaseFacts {
        marker,
        catalogue_id: id.map(str::to_string),
    }
}

fn unavailable(code: &'static str, page: bool) -> ZeroServe {
    ZeroServe::Unavailable { code, page }
}

#[test]
fn the_selector_and_the_marker_decide() {
    let store = MemRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let base = first_record(&chain);
    let fresh = || Seen::default();

    // Today: d1, no stamp, no marker.
    assert_eq!(
        decide(&base, &db(false, Some("main")), &mut fresh()),
        ZeroServe::Serve
    );
    // The move's window: the marker is written, the flip is not.
    assert_eq!(
        decide(&base, &db(true, Some("main")), &mut fresh()),
        ZeroServe::Serve
    );
    // After the flip: moved, whatever the database says.
    let flipped = with(&base, zero(moved(), Some(7), None, None));
    for facts in [db(false, None), db(true, Some("main"))] {
        assert_eq!(
            decide(&flipped, &facts, &mut fresh()),
            unavailable("tenant_zero_moved", false)
        );
    }
    // A d1 head with a cutover stamp and no undo: a database left behind.
    let left = with(&base, zero(Selector::D1, Some(7), None, None));
    for facts in [db(true, Some("main")), db(false, Some("main"))] {
        assert_eq!(
            decide(&left, &facts, &mut fresh()),
            unavailable("database_left_behind", true)
        );
    }
    // After a stamped undo: only the database the record names serves.
    let undone = with(&base, zero(Selector::D1, Some(7), Some(9), Some("main2")));
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
            unavailable("database_is_not_the_named_one", true)
        );
    }
    // An undo stamp that is not above the cutover stamp is no undo.
    let bad = with(&base, zero(Selector::D1, Some(7), Some(7), Some("main2")));
    assert_eq!(
        decide(&bad, &db(false, Some("main2")), &mut fresh()),
        unavailable("database_left_behind", true)
    );
    // Not tenant 0, or no selector: damage.
    let mut other = base.clone();
    other.tenant = t1();
    assert_eq!(
        decide(&other, &db(false, None), &mut fresh()),
        unavailable("not_tenant_zero", true)
    );
    let mut none = base.clone();
    none.tenant_zero = None;
    assert_eq!(
        decide(&none, &db(false, None), &mut fresh()),
        unavailable("selector_missing", true)
    );
}

/// An isolate that has seen `moved` goes back to d1 only on a head with an
/// undo stamp above what it saw and a catalogue id its database carries.
#[test]
fn moved_is_sticky_until_a_stamped_undo() {
    let store = MemRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let base = first_record(&chain);
    let mut seen = Seen::default();
    let flipped = with(&base, zero(moved(), Some(7), None, None));
    let facts = db(false, Some("main2"));
    assert_eq!(
        decide(&flipped, &facts, &mut seen),
        unavailable("tenant_zero_moved", false)
    );
    assert_eq!(seen.moved_at_stamp, Some(7));

    // A rolled-back or forged view: d1 with no undo.
    assert_eq!(
        decide(&base, &facts, &mut seen),
        unavailable("selector_went_back", true)
    );
    // An undo stamp not above the cutover stamp this isolate saw.
    let stale = with(&base, zero(Selector::D1, Some(5), Some(6), Some("main2")));
    assert_eq!(
        decide(&stale, &facts, &mut seen),
        unavailable("selector_went_back", true)
    );
    assert_eq!(seen.moved_at_stamp, Some(7));
    // The stamped undo, on the named database.
    let undone = with(&base, zero(Selector::D1, Some(7), Some(8), Some("main2")));
    assert_eq!(
        decide(&undone, &db(false, Some("main")), &mut seen),
        unavailable("database_is_not_the_named_one", true)
    );
    assert_eq!(decide(&undone, &facts, &mut seen), ZeroServe::Serve);
    assert_eq!(seen.moved_at_stamp, None);
}

/// The isolate reads tenant 0's head once, checks it every RECHECK_MS by
/// one listing, and reads it again when it moved.
#[test]
fn the_watch_rechecks_the_head_and_follows_a_move() {
    let store = MemRecords::new();
    let seal = PlainSeal::new();
    let chain = TenantChain {
        store: &store,
        seal: &seal,
    };
    let base = first_record(&chain);
    let facts = db(false, Some("main2"));
    let mut watch = ZeroWatch::default();
    block_on(async {
        assert_eq!(watch.serve(&chain, &facts, NOW).await, ZeroServe::Serve);
        // The flip lands.
        let flipped = plant(&store, &seal, &base, zero(moved(), Some(7), None, None));
        // Inside the interval the cached head stands, with no listing.
        let lists = store.lists();
        let soon = UnixMs(NOW.0 + RECHECK_MS - 1);
        assert_eq!(watch.serve(&chain, &facts, soon).await, ZeroServe::Serve);
        assert_eq!(store.lists(), lists);
        // After it, the head is checked and read again.
        let later = UnixMs(NOW.0 + RECHECK_MS);
        assert_eq!(
            watch.serve(&chain, &facts, later).await,
            unavailable("tenant_zero_moved", false)
        );
        assert_eq!(store.lists(), lists + 1);
        // A head that goes back to d1 without an undo is refused.
        let back = plant(
            &store,
            &seal,
            &flipped,
            zero(Selector::D1, Some(7), None, None),
        );
        let t = UnixMs(later.0 + RECHECK_MS);
        assert_eq!(
            watch.serve(&chain, &facts, t).await,
            unavailable("selector_went_back", true)
        );
        // The stamped undo serves again.
        plant(
            &store,
            &seal,
            &back,
            zero(Selector::D1, Some(7), Some(9), Some("main2")),
        );
        let t = UnixMs(t.0 + RECHECK_MS);
        assert_eq!(watch.serve(&chain, &facts, t).await, ZeroServe::Serve);
        // A clock that goes back does not keep a stale head.
        let back_in_time = UnixMs(NOW.0);
        let lists = store.lists();
        watch.serve(&chain, &facts, back_in_time).await;
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
    let facts = db(false, Some("main"));
    block_on(async {
        // No record at all: damage, paged.
        let mut watch = ZeroWatch::default();
        assert_eq!(
            watch.serve(&chain, &facts, NOW).await,
            unavailable("record_damaged", true)
        );
    });
    first_record(&chain);
    block_on(async {
        let mut watch = ZeroWatch::default();
        assert_eq!(watch.serve(&chain, &facts, NOW).await, ZeroServe::Serve);
        // R2 fails at the next check: 503, an outage and not damage.
        store.fail_lists(true);
        let t = UnixMs(NOW.0 + RECHECK_MS);
        assert_eq!(
            watch.serve(&chain, &facts, t).await,
            unavailable("record_unreadable", false)
        );
    });
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
            db(true, Some("main"))
        );
    });
}

#[test]
fn a_failed_directory_read_is_not_an_unknown_key() {
    let never = || -> bool { panic!("tenant 0 must not be asked") };
    let no_record = || -> Option<TenantId> { panic!("no route record must be read") };
    // A directory that was read decides.
    assert_eq!(
        route_without_directory(
            DirectoryAnswer::Read(Some(t1())),
            ZeroServe::Serve,
            never,
            no_record
        ),
        Route::Tenant(t1())
    );
    assert_eq!(
        route_without_directory(
            DirectoryAnswer::Read(None),
            ZeroServe::Serve,
            never,
            no_record
        ),
        Route::UnknownKey
    );
    // A failed read: tenant 0's catalogue is asked while it serves.
    assert_eq!(
        route_without_directory(
            DirectoryAnswer::Failed,
            ZeroServe::Serve,
            || true,
            no_record
        ),
        Route::Tenant(TenantId::zero())
    );
    // Not tenant 0's key: the route record, or 503.
    assert_eq!(
        route_without_directory(
            DirectoryAnswer::Failed,
            ZeroServe::Serve,
            || false,
            || Some(t1())
        ),
        Route::Tenant(t1())
    );
    assert_eq!(
        route_without_directory(DirectoryAnswer::Failed, ZeroServe::Serve, || false, || None),
        Route::Unavailable
    );
    // After the move tenant 0's catalogue is not asked at all.
    let asked = Cell::new(false);
    let r = route_without_directory(
        DirectoryAnswer::Failed,
        unavailable("tenant_zero_moved", false),
        || {
            asked.set(true);
            true
        },
        || Some(t1()),
    );
    assert_eq!(r, Route::Tenant(t1()));
    assert!(!asked.get());
    // A route record never names tenant 0.
    assert_eq!(
        route_without_directory(
            DirectoryAnswer::Failed,
            unavailable("tenant_zero_moved", false),
            || false,
            || Some(TenantId::zero())
        ),
        Route::Unavailable
    );
}
