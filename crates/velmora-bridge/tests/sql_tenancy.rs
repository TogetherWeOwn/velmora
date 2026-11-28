//! The tenancy catalogue contract on the selected SQLite or PostgreSQL backend.

use velmora_bridge::sql::SqlCatalog;
use velmora_bridge::testkit::TestSql;
use velmora_bridge::{
    BridgeError, Bucket, BucketId, Catalog, Guard, SqlValue, TenantState, UnixMs,
};

const NOW: UnixMs = UnixMs(100);
const LATER: UnixMs = UnixMs(200);
const OWNER: &str = "t_1234567890123456";
const OTHER_OWNER: &str = "t_1234567890123457";

fn catalogue() -> SqlCatalog<TestSql> {
    SqlCatalog::new(TestSql::with_schema().unwrap())
}

#[tokio::test]
async fn tenant_create_keeps_the_original_fields_on_retry() {
    let cat = catalogue();
    assert_eq!(cat.tenant_get(OWNER).await.unwrap(), None);
    assert_eq!(
        cat.tenant_by_external_ref("workspace-a").await.unwrap(),
        None
    );

    let first = cat.tenant_create("workspace-a", None, NOW).await.unwrap();
    let id = first.id.strip_prefix("t_").unwrap();
    assert_eq!(id.len(), 16);
    assert_ne!(id, "0000000000000000");
    assert!(id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    assert_eq!(first.external_ref, "workspace-a");
    assert_eq!(first.display_name, None);
    assert_eq!(first.state, TenantState::Active);
    assert_eq!(first.suspension_mode, None);
    assert_eq!(first.created_at, NOW);
    assert_eq!(first.updated_at, NOW);
    assert_eq!(
        cat.tenant_create("workspace-a", Some("Changed"), LATER)
            .await
            .unwrap(),
        first
    );
    assert_eq!(
        cat.tenant_get(&first.id).await.unwrap(),
        Some(first.clone())
    );
    assert_eq!(
        cat.tenant_by_external_ref("workspace-a").await.unwrap(),
        Some(first)
    );
}

#[tokio::test]
async fn concurrent_tenant_creates_share_one_identity() {
    let cat = catalogue();
    let (first, second) = tokio::join!(
        cat.tenant_create("workspace-race", Some("First"), NOW),
        cat.tenant_create("workspace-race", Some("Second"), LATER),
    );
    let first = first.unwrap();
    assert_eq!(second.unwrap(), first);
    let count = cat
        .sql
        .fixture_query(
            "SELECT count(*) FROM tenants WHERE external_ref = ?1",
            &[SqlValue::Text("workspace-race".into())],
        )
        .await
        .unwrap();
    assert_eq!(count, vec![vec![SqlValue::Int(1)]]);
}

#[tokio::test]
async fn tenant_inputs_are_bounded_before_reaching_sql() {
    let cat = catalogue();
    for reference in [
        "",
        "workspace\n",
        "workspace A",
        "team.a",
        "café",
        &"x".repeat(127),
    ] {
        assert!(matches!(
            cat.tenant_create(reference, None, NOW).await,
            Err(BridgeError::Invalid(_))
        ));
        assert!(matches!(
            cat.tenant_by_external_ref(reference).await,
            Err(BridgeError::Invalid(_))
        ));
    }
    assert!(matches!(
        cat.tenant_create("workspace", Some(&"é".repeat(101)), NOW)
            .await,
        Err(BridgeError::Invalid(_))
    ));
    assert!(matches!(
        cat.tenant_create("workspace", Some("bad\0name"), NOW).await,
        Err(BridgeError::Invalid(_))
    ));
    assert!(matches!(
        cat.tenant_get("t_0000000000000000").await,
        Err(BridgeError::Invalid(_))
    ));
    let max_ref = format!("Ab_1:c-{}", "x".repeat(119));
    assert_eq!(max_ref.len(), 126);
    let max_name = "é".repeat(100);
    assert_eq!(
        cat.tenant_create(&max_ref, Some(&max_name), NOW)
            .await
            .unwrap()
            .display_name
            .as_deref(),
        Some(max_name.as_str())
    );
}

#[tokio::test]
async fn tenant_reads_require_a_consistent_state_and_suspension_mode() {
    use velmora_bridge::TenantSuspensionMode;

    let cat = catalogue();
    let id = cat.tenant_create("workspace", None, NOW).await.unwrap().id;
    let set_state = |state: &str, mode: Option<&str>| {
        let args = [
            SqlValue::Text(state.into()),
            mode.map_or(SqlValue::Null, |mode| SqlValue::Text(mode.into())),
            SqlValue::Text(id.clone()),
        ];
        let sql = &cat.sql;
        async move {
            sql.fixture_exec(
                "UPDATE tenants SET state = ?1, suspension_mode = ?2 WHERE id = ?3",
                &args,
            )
            .await
            .unwrap();
        }
    };
    for (stored_state, stored_mode, expected_state, expected_mode) in [
        ("active", None, TenantState::Active, None),
        ("deleting", None, TenantState::Deleting, None),
        (
            "suspended",
            Some("read_only"),
            TenantState::Suspended,
            Some(TenantSuspensionMode::ReadOnly),
        ),
        (
            "suspended",
            Some("blocked"),
            TenantState::Suspended,
            Some(TenantSuspensionMode::Blocked),
        ),
    ] {
        set_state(stored_state, stored_mode).await;
        let row = cat.tenant_get(&id).await.unwrap().unwrap();
        assert_eq!(
            (row.state, row.suspension_mode),
            (expected_state, expected_mode)
        );
    }
    for (state, mode) in [
        ("unknown", None),
        ("suspended", None),
        ("suspended", Some("unknown")),
        ("active", Some("read_only")),
        ("deleting", Some("blocked")),
    ] {
        set_state(state, mode).await;
        assert!(matches!(
            cat.tenant_get(&id).await,
            Err(BridgeError::Sql(_))
        ));
    }
}

async fn add_bucket(cat: &SqlCatalog<TestSql>, name: &str, owner: &str) {
    let bucket = Bucket {
        id: BucketId::new(format!("b_{name}")),
        name: name.into(),
        owner: owner.into(),
        bdk_wrapped: vec![0; 73],
        kek_version: 1,
        disposable: false,
        created_at: NOW,
    };
    assert_eq!(
        cat.create_bucket(&bucket).await.unwrap(),
        Guard::Applied(())
    );
}

#[tokio::test]
async fn bucket_pages_are_owner_scoped_and_use_an_exclusive_name_cursor() {
    let cat = catalogue();
    add_bucket(&cat, "alpha", OWNER).await;
    add_bucket(&cat, "charlie", OWNER).await;
    add_bucket(&cat, "delta", OTHER_OWNER).await;
    let first = cat.buckets_by_owner(OWNER, None, 1).await.unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].name, "alpha");

    add_bucket(&cat, "able", OWNER).await;
    add_bucket(&cat, "bravo", OWNER).await;
    let next = cat
        .buckets_by_owner(OWNER, Some(&first[0].name), 1000)
        .await
        .unwrap();
    assert_eq!(
        next.into_iter().map(|b| b.name).collect::<Vec<_>>(),
        ["bravo", "charlie"]
    );
    assert!(cat
        .buckets_by_owner(OWNER, Some("charlie"), 1)
        .await
        .unwrap()
        .is_empty());
    assert!(matches!(
        cat.buckets_by_owner(OWNER, None, 1001).await,
        Err(BridgeError::Invalid(_))
    ));
}

#[tokio::test]
async fn disabled_token_retries_keep_the_first_record() {
    let cat = catalogue();
    let digest = "a".repeat(64);
    assert!(!cat.mgmt_token_is_disabled(&digest).await.unwrap());
    cat.mgmt_token_disable(&digest, "standard", "rotated", NOW)
        .await
        .unwrap();
    cat.mgmt_token_disable(&digest, "confirmed", "leaked", LATER)
        .await
        .unwrap();
    assert!(cat.mgmt_token_is_disabled(&digest).await.unwrap());
    assert!(!cat.mgmt_token_is_disabled(&"b".repeat(64)).await.unwrap());
    let row = cat.sql.fixture_query(
        "SELECT token_class, reason, disabled_at_ms FROM mgmt_tokens_disabled WHERE token_sha256 = ?1",
        &[SqlValue::Text(digest)],
    ).await.unwrap();
    assert_eq!(
        row,
        vec![vec![
            SqlValue::Text("standard".into()),
            SqlValue::Text("rotated".into()),
            SqlValue::Int(NOW.0)
        ]]
    );
}

#[tokio::test]
async fn disabled_token_store_refuses_non_digests_and_non_registry_values() {
    let cat = catalogue();
    for digest in ["", &"a".repeat(63), &"A".repeat(64), &"g".repeat(64)] {
        assert!(matches!(
            cat.mgmt_token_is_disabled(digest).await,
            Err(BridgeError::Invalid(_))
        ));
        assert!(matches!(
            cat.mgmt_token_disable(digest, "standard", "rotated", NOW)
                .await,
            Err(BridgeError::Invalid(_))
        ));
    }
    let digest = "a".repeat(64);
    assert!(matches!(
        cat.mgmt_token_disable(&digest, "unknown", "rotated", NOW)
            .await,
        Err(BridgeError::Invalid(_))
    ));
    assert!(matches!(
        cat.mgmt_token_disable(&digest, "standard", "arbitrary note", NOW)
            .await,
        Err(BridgeError::Invalid(_))
    ));
    assert!(!cat.mgmt_token_is_disabled(&digest).await.unwrap());
}
