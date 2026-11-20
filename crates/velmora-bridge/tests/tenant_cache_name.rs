//! The one name the cache store gets, end to end.
//!
//! The service writes to the cache store in one place: a cold read
//! fills it with the extent it read back and verified. This test does
//! that against the in-process NNTP server and holds the name.
//!
//! It is apart from `tenant_goldens.rs` because it needs the NNTP rig.
//! Like that file it passed on the code before the tenant seams and is
//! not changed by them.

mod nntp_support;

use nntp_support::*;
use velmora_bridge::fetch::ColdFetch;
use velmora_bridge::*;

#[tokio::test]
async fn a_cold_read_fills_the_cache_under_the_name_it_did() {
    let rig = simple_rig().await;
    let s = rig.seed(1, &marked_plaintext(200_000)).await;
    rig.post(&s).await;
    // Usenet is the only source left.
    let safety_name = format!("x/{}", s.extent.as_str());
    assert!(rig.bridge.safety.contains(&safety_name));
    rig.bridge.safety.delete(&safety_name).await.unwrap();
    assert_eq!(rig.bridge.cache.keys(), Vec::<String>::new());

    let extent = rig.bridge.catalog.extent(&s.extent);
    let read = rig.bridge.fetch_cold(&extent).await.unwrap();
    assert_eq!(read, ColdFetch::Filled(s.cipher.clone()));

    assert_eq!(
        rig.bridge.cache.keys(),
        [format!("c/{}", s.extent.as_str())]
    );
    assert!(!rig.bridge.safety.keys().iter().any(|k| k.starts_with("x/")));
}
