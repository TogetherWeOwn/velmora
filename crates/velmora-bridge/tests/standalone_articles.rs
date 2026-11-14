//! Standalone yEnc articles: a new plan posts every article as its own
//! single-part yEnc file under its own random name, with nothing that ties
//! the articles of one extent together. A row planned before that keeps
//! the multi-part form it was posted in. Both forms post, repost
//! byte-identically, verify and read back cold.

mod nntp_support;

use nntp_support::*;
use velmora::yenc::decode_part_to;
use velmora_bridge::fetch::ColdFetch;
use velmora_bridge::recovery::ArticleManifest;
use velmora_bridge::*;

/// Three articles: one full article 0 (header plus 11 chunks), one full,
/// one short.
const PLAIN_LEN: usize = 1_500_000;
/// Usenet providers commonly cap an article near 1 MiB; ours stay under.
const ARTICLE_BOUND: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Form {
    Standalone,
    Legacy,
}

/// The yEnc framing lines of a posted article: `=ybegin`, the `=ypart`
/// line if any, and `=yend`.
struct Framing {
    begin: String,
    part: Option<String>,
    end: String,
}

fn framing(article: &[u8]) -> Framing {
    let text = String::from_utf8_lossy(article);
    let line = |prefix: &str| {
        text.split("\r\n")
            .find(|l| l.starts_with(prefix))
            .map(str::to_owned)
    };
    Framing {
        begin: line("=ybegin ").expect("=ybegin line"),
        part: line("=ypart "),
        end: line("=yend ").expect("=yend line"),
    }
}

impl Rig {
    /// Seeds an extent and posts it in `form`. A legacy plan is made the
    /// way an older version left it: the plan is stored while posting is
    /// refused, then its rows lose their own yEnc name.
    async fn posted_as(&self, n: u8, form: Form) -> (Seeded, Vec<ArticleRow>) {
        let s = self.seed(n, &marked_plaintext(PLAIN_LEN)).await;
        if form == Form::Legacy {
            self.server().set_posting_allowed(false).await;
            assert_ne!(self.run_post(&s).await, JobOutcome::Ack);
            self.server().set_posting_allowed(true).await;
            self.bridge.catalog.edit(&s.extent, |e| {
                for a in &mut e.articles {
                    a.yenc_name = None;
                }
            });
            self.bridge.clock.advance_secs(60);
        }
        let plan = self.post(&s).await;
        let named = plan.iter().all(|a| a.yenc_name.is_some());
        assert_eq!(named, form == Form::Standalone, "{form:?}");
        (s, plan)
    }

    async fn article(&self, id: &str) -> Vec<u8> {
        let mut client = self.raw_client(0).await;
        let mut article = Vec::new();
        client.article_to(id, &mut article).await.unwrap();
        client.quit().await;
        article
    }

    async fn body(&self, id: &str) -> Vec<u8> {
        let mut client = self.raw_client(0).await;
        let mut body = Vec::new();
        NntpSession::body(&mut client, id, &mut body).await.unwrap();
        NntpSession::quit(client).await;
        body
    }
}

/// A new plan: every article is `=ybegin line=128 size=<own payload>
/// name=<own random name>`, no `=ypart`, `=yend size=<own payload>
/// crc32=`. No part number, no range and no extent size reach the wire,
/// and the name has nothing in common with the message-id.
#[tokio::test]
async fn new_plans_post_standalone_single_part_articles() {
    let rig = simple_rig().await;
    let (s, plan) = rig.posted_as(1, Form::Standalone).await;
    assert_eq!(plan.len(), 3);
    let extent_size = format!("size={}", s.cipher.len());
    let mut names = std::collections::BTreeSet::new();
    for row in &plan {
        let name = row.yenc_name.clone().unwrap();
        assert_eq!(name.len(), 12);
        assert!(name
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase()));
        assert!(!row.message_id.contains(&name), "the name echoes the id");
        names.insert(name.clone());

        let article = rig.article(&row.message_id).await;
        let f = framing(&article);
        assert_eq!(
            f.begin,
            format!("=ybegin line=128 size={} name={name}", row.cipher_len)
        );
        assert_eq!(f.part, None);
        let crc_at = f.end.find(" crc32=").expect("crc32= in =yend");
        assert_eq!(&f.end[..crc_at], format!("=yend size={}", row.cipher_len));
        assert_eq!(f.end.len() - crc_at, " crc32=".len() + 8);
        for multipart in ["part=", "total=", "pcrc32=", "begin=", "end="] {
            assert!(!f.begin.contains(multipart) && !f.end.contains(multipart));
        }
        assert!(!String::from_utf8_lossy(&article).contains(&extent_size));

        // The checksum is of this article's payload alone.
        let mut payload = vec![0u8; row.cipher_len as usize];
        let part = decode_part_to(
            &row.message_id,
            &rig.body(&row.message_id).await,
            &mut payload,
        )
        .unwrap();
        assert!(!part.multipart);
        assert_eq!(part.written as u64, row.cipher_len);
        let start = row.cipher_offset as usize;
        assert_eq!(payload, s.cipher[start..start + payload.len()]);
        assert!(article.len() <= ARTICLE_BOUND, "{} bytes", article.len());
    }
    assert_eq!(names.len(), plan.len(), "every article has its own name");
}

/// A row planned before standalone articles is posted in the multi-part
/// form it always had: part `idx + 1` of the extent's articles, its range,
/// and the name taken from the message-id.
#[tokio::test]
async fn legacy_rows_keep_the_multi_part_form() {
    let rig = simple_rig().await;
    let (s, plan) = rig.posted_as(2, Form::Legacy).await;
    for row in &plan {
        let article = rig.article(&row.message_id).await;
        let f = framing(&article);
        assert_eq!(
            f.begin,
            format!(
                "=ybegin part={} total=3 line=128 size={} name={}",
                row.idx + 1,
                s.cipher.len(),
                &row.message_id[..12]
            )
        );
        assert_eq!(
            f.part,
            Some(format!(
                "=ypart begin={} end={}",
                row.cipher_offset + 1,
                row.cipher_offset + row.cipher_len
            ))
        );
        assert!(f.end.starts_with(&format!(
            "=yend size={} part={} pcrc32=",
            row.cipher_len,
            row.idx + 1
        )));
        let mut payload = vec![0u8; row.cipher_len as usize];
        let part = decode_part_to(
            &row.message_id,
            &rig.body(&row.message_id).await,
            &mut payload,
        )
        .unwrap();
        assert!(part.multipart);
        assert_eq!(part.part_number, Some(u64::from(row.idx) + 1));
        assert!(article.len() <= ARTICLE_BOUND, "{} bytes", article.len());
    }
}

/// The provider loses an article after the first post; the job's
/// successor posts it again, and the stored bytes are the same, in
/// either form.
async fn repost_is_byte_identical_in(form: Form, n: u8) {
    let rig = simple_rig().await;
    let s = rig.seed(n, &marked_plaintext(PLAIN_LEN)).await;
    if form == Form::Legacy {
        rig.server().set_posting_allowed(false).await;
        assert_ne!(rig.run_post(&s).await, JobOutcome::Ack);
        rig.server().set_posting_allowed(true).await;
        rig.bridge.catalog.edit(&s.extent, |e| {
            for a in &mut e.articles {
                a.yenc_name = None;
            }
        });
        rig.bridge.clock.advance_secs(LEASE_SECS + 1);
    }
    rig.bridge.catalog.fail_mark_posted.set(1);
    rig.run_post(&s).await;
    let plan = rig.plan(&s).await;
    assert_eq!(plan[0].yenc_name.is_some(), form == Form::Standalone);
    let id = plan[0].message_id.clone();
    let first = rig.article(&id).await;

    rig.server().hide(&id).await;
    rig.bridge.clock.advance_secs(LEASE_SECS + 1);
    assert_eq!(rig.run_post(&s).await, JobOutcome::Ack);
    let second = rig.article(&id).await;
    assert!(!first.is_empty());
    assert_eq!(first, second, "{form:?}");
    assert_eq!(rig.server().posted_count().await, 3);
}

#[tokio::test]
async fn repost_of_a_standalone_article_is_byte_identical() {
    repost_is_byte_identical_in(Form::Standalone, 3).await;
}

#[tokio::test]
async fn repost_of_a_legacy_article_is_byte_identical() {
    repost_is_byte_identical_in(Form::Legacy, 4).await;
}

/// Verification and a cold read rely on the stored offsets, lengths and
/// SHA-256 alone, never on yEnc part numbers: both forms pass.
async fn verify_and_cold_read_in(form: Form, n: u8) {
    let rig = simple_rig().await;
    let (s, _) = rig.posted_as(n, form).await;
    assert_eq!(rig.run(&s, OutboxStage::Verify).await, JobOutcome::Ack);
    let rows = rig.bridge.catalog.verifications(&s.extent);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].result, VerifyResult::Ok, "{form:?}");
    assert_eq!((rows[0].articles_ok, rows[0].articles_total), (3, 3));

    rig.bridge
        .safety
        .delete(&s.extent.safety_key())
        .await
        .unwrap();
    let extent = rig.bridge.catalog.extent(&s.extent);
    assert_eq!(
        rig.bridge.fetch_cold(&extent).await.unwrap(),
        ColdFetch::Filled(s.cipher.clone()),
        "{form:?}"
    );
}

#[tokio::test]
async fn standalone_articles_verify_and_read_cold() {
    verify_and_cold_read_in(Form::Standalone, 5).await;
}

#[tokio::test]
async fn legacy_articles_verify_and_read_cold() {
    verify_and_cold_read_in(Form::Legacy, 6).await;
}

/// The recovery record carries each row's yEnc name, so a replayed row
/// reposts in its own form. A record of a legacy row has no `yenc_name`
/// key at all (the same bytes as before) and reads back as legacy.
#[tokio::test]
async fn the_plan_record_keeps_each_rows_form() {
    let rig = simple_rig().await;
    let (s, mut plan) = rig.posted_as(7, Form::Standalone).await;
    plan[1].yenc_name = None;
    let extent = rig.bridge.catalog.extent(&s.extent);
    let record = ArticleManifest::new(&extent, &plan);
    let json = serde_json::to_value(&record).unwrap();
    let articles = json["articles"].as_array().unwrap();
    assert_eq!(articles[0]["yenc_name"], plan[0].yenc_name.clone().unwrap());
    assert!(articles[1].get("yenc_name").is_none());

    let back: ArticleManifest = serde_json::from_value(json).unwrap();
    let rows = back.rows(ArticleState::Posted).unwrap();
    let names: Vec<_> = rows.iter().map(|a| a.yenc_name.clone()).collect();
    let want: Vec<_> = plan.iter().map(|a| a.yenc_name.clone()).collect();
    assert_eq!(names, want);
}
