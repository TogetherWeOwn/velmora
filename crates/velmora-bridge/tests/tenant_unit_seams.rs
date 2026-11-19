//! The two seams for more than one catalogue: the id a bridge raises
//! its rollback stamp under, and the directory.
//!
//! Neither changes what the service does. The id is the configured one,
//! as before, and the directory is asked by nothing yet; the source
//! tests in `tenant_seams.rs` hold both.

mod service_support;

use service_support::*;
use velmora_bridge::directory::{Directory, SingleTenant};
use velmora_bridge::stamp::StampRow;
use velmora_bridge::*;

fn stamps<N: NntpConnector + 'static>(rig: &Rig<N>) -> Vec<String> {
    let mut keys: Vec<String> = rig
        .bridge
        .safety
        .keys()
        .into_iter()
        .filter(|k| k.starts_with("rs/"))
        .collect();
    keys.sort();
    keys
}

/// The id of a bridge's catalogue is the configured one: `main` when
/// nothing is set. It is not made from a tenant.
#[test]
fn the_catalogue_id_of_a_bridge_is_the_configured_one() {
    let rig = rig_with(NoNntp, config(Vec::new()));
    assert_eq!(rig.bridge.catalogue_id(), "main");
    assert_eq!(rig.bridge.catalogue_id(), rig.bridge.cfg.catalogue_id);

    let mut cfg = config(Vec::new());
    cfg.catalogue_id = "drill-7".to_string();
    let rig = rig_with(NoNntp, cfg);
    assert_eq!(rig.bridge.catalogue_id(), "drill-7");
}

/// A raise names its stamp object and its row by that id, as it did
/// when it read the configuration itself.
#[tokio::test(flavor = "current_thread")]
async fn a_raise_goes_under_the_catalogue_id_of_the_bridge() {
    for id in ["main", "drill-7"] {
        let mut cfg = config(Vec::new());
        cfg.catalogue_id = id.to_string();
        let rig = rig_with(NoNntp, cfg);
        rig.bridge.raise_stamp().await.unwrap();
        rig.bridge.raise_stamp().await.unwrap();
        assert_eq!(
            stamps(&rig),
            [
                format!("rs/{id}/00000000000000000001"),
                format!("rs/{id}/00000000000000000002"),
            ]
        );
        assert_eq!(
            rig.bridge.catalog.stamp(id).await.unwrap(),
            StampRow {
                counter: Some(2),
                rolled_back: false,
            }
        );
    }
}

/// The directory of a store with one tenant: every access key id is a
/// key of tenant 0. Whether there is such a key is not the directory's
/// to say; the key row in the catalogue decides that.
#[tokio::test(flavor = "current_thread")]
async fn the_directory_of_one_tenant_routes_every_key_to_tenant_zero() {
    let directory = SingleTenant;
    for key in ["VKIA0000000000000000", "never-made", ""] {
        let route = directory.route(key).await.unwrap();
        assert_eq!(route, Some(TenantScope::tenant_zero()), "{key:?}");
    }
}

/// A directory can answer "no such key", and that answer is not an
/// error: a caller fails closed on it and never guesses a tenant.
#[tokio::test(flavor = "current_thread")]
async fn a_directory_can_say_that_it_does_not_know_a_key() {
    struct Empty;
    impl Directory for Empty {
        async fn route(&self, _access_key_id: &str) -> Result<Option<TenantScope>> {
            Ok(None)
        }
    }
    assert_eq!(Empty.route("VKIA0000000000000000").await.unwrap(), None);
}
