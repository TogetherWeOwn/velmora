//! DeleteObjects documents, and the ListMultipartUploads and ListParts
//! pages: what is parsed, what is refused, and what the XML says.

use velmora_s3_proto::multipart_listing::{ListParts, ListUploads, PartEntry, UploadEntry};
use velmora_s3_proto::mutation::{delete_result, parse_delete, DeleteOutcome};
use velmora_s3_proto::*;

/// 2026-11-13T00:00:00Z.
const T0: i64 = 1_794_528_000_000;

fn policy() -> Policy {
    policy_with(256 * 1024)
}

fn policy_with(control_xml_bytes: usize) -> Policy {
    // Fixture values only.
    Policy::new(
        "s3.example.test".into(),
        "auto".into(),
        Limits {
            target_bytes: 8192,
            control_xml_bytes,
            header_bytes: 16384,
            header_count: 64,
            query_pairs: 64,
            upload_bytes: 1024,
            clock_skew_seconds: 900,
            presign_seconds: 60,
        },
    )
    .unwrap()
}

fn target(raw: &str) -> Target {
    Target::parse(raw, &policy()).unwrap()
}

fn text(resp: &Response) -> String {
    assert_eq!(resp.status, 200);
    String::from_utf8(resp.body.clone()).unwrap()
}

/// The text of every `<tag>…</tag>` in `xml`, in order.
fn values(xml: &str, tag: &str) -> Vec<String> {
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        rest = &rest[i + open.len()..];
        let j = rest.find(&close).unwrap();
        out.push(rest[..j].to_string());
        rest = &rest[j + close.len()..];
    }
    out
}

fn delete_xml(keys: usize) -> String {
    let mut xml = String::from("<Delete>");
    for i in 0..keys {
        xml.push_str(&format!("<Object><Key>k{i}</Key></Object>"));
    }
    xml.push_str("</Delete>");
    xml
}

// ---------------------------------------------------------------------------
// DeleteObjects
// ---------------------------------------------------------------------------

#[test]
fn a_delete_document_names_its_keys_in_order() {
    let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
               <Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
               <Object><Key>b</Key></Object><Object><Key>a &amp; &lt;c&gt;</Key></Object>\
               <Object><Key>b</Key></Object><Quiet>true</Quiet></Delete>";
    let request = parse_delete(xml.as_bytes(), &policy(), 1000).unwrap();
    assert_eq!(request.keys, ["b", "a & <c>", "b"]);
    assert!(request.quiet);

    let request = parse_delete(delete_xml(1000).as_bytes(), &policy(), 1000).unwrap();
    assert_eq!(request.keys.len(), 1000);
    assert!(!request.quiet);
}

#[test]
fn a_delete_document_that_is_not_one_is_refused() {
    let malformed = |xml: &str| parse_delete(xml.as_bytes(), &policy(), 1000).unwrap_err();
    // More keys than one request may name.
    assert_eq!(malformed(&delete_xml(1001)), ErrorCode::MalformedXML);
    // The caller's own limit holds too, and S3's caps it.
    assert_eq!(
        parse_delete(delete_xml(3).as_bytes(), &policy(), 2).unwrap_err(),
        ErrorCode::MalformedXML
    );
    assert_eq!(
        parse_delete(delete_xml(1001).as_bytes(), &policy(), 5000).unwrap_err(),
        ErrorCode::MalformedXML
    );
    // No key at all.
    assert_eq!(malformed("<Delete></Delete>"), ErrorCode::MalformedXML);
    assert_eq!(
        malformed("<Delete><Quiet>true</Quiet></Delete>"),
        ErrorCode::MalformedXML
    );
    // Not XML, cut short, or another document.
    assert_eq!(malformed(""), ErrorCode::MalformedXML);
    assert_eq!(malformed("not xml"), ErrorCode::MalformedXML);
    assert_eq!(
        malformed("<Delete><Object><Key>k</Key></Object>"),
        ErrorCode::MalformedXML
    );
    assert_eq!(
        malformed("<Remove><Object><Key>k</Key></Object></Remove>"),
        ErrorCode::MalformedXML
    );
    // What this service does not do is refused, never ignored: a version
    // to delete, an empty key, an unknown element, a second Quiet.
    for xml in [
        "<Delete><Object><Key>k</Key><VersionId>v</VersionId></Object></Delete>",
        "<Delete><Object><Key></Key></Object></Delete>",
        "<Delete><Object><Key>k</Key></Object><Other/></Delete>",
        "<Delete><Quiet>true</Quiet><Quiet>false</Quiet><Object><Key>k</Key></Object></Delete>",
    ] {
        assert!(
            parse_delete(xml.as_bytes(), &policy(), 1000).is_err(),
            "{xml}"
        );
    }
    assert_eq!(
        malformed("<Delete><Quiet>maybe</Quiet><Object><Key>k</Key></Object></Delete>"),
        ErrorCode::InvalidArgument
    );
    // A condition on one of the keys (delete it only if it is this
    // object) is not evaluated, and says so.
    for condition in [
        "<ETag>&quot;0123456789abcdef0123456789abcdef&quot;</ETag>",
        "<LastModifiedTime>Fri, 15 Jan 2027 08:00:00 GMT</LastModifiedTime>",
        "<Size>7</Size>",
    ] {
        for object in [
            format!("<Key>k</Key>{condition}"),
            format!("{condition}<Key>k</Key>"),
        ] {
            assert_eq!(
                malformed(&format!(
                    "<Delete><Object><Key>a</Key></Object><Object>{object}</Object></Delete>"
                )),
                ErrorCode::NotImplemented,
                "{object}"
            );
        }
    }
    // A document over the size limit of the policy.
    assert!(parse_delete(delete_xml(10).as_bytes(), &policy_with(64), 1000).is_err());
}

/// The count of elements is capped while the document is read, not after
/// a tree of it is built: 1000 entries and `Quiet` fit, and one element
/// more is refused whatever it is.
#[test]
fn a_delete_document_may_open_only_as_many_elements_as_1000_entries_need() {
    let entries = "<Object><Key>k</Key></Object>".repeat(1000);
    let full = format!("<Delete><Quiet>true</Quiet>{entries}</Delete>");
    let request = parse_delete(full.as_bytes(), &policy(), 1000).unwrap();
    assert_eq!((request.keys.len(), request.quiet), (1000, true));
    let malformed = |xml: &str| parse_delete(xml.as_bytes(), &policy(), 1000).unwrap_err();

    // A few unknown elements are an invalid request ...
    let few = format!("<Delete>{}</Delete>", "<a></a>".repeat(5));
    assert_eq!(malformed(&few), ErrorCode::InvalidRequest);
    // ... and past the cap the document is refused as malformed, before
    // the unknown element is looked at.
    let unknown = format!("<Delete>{}</Delete>", "<a></a>".repeat(2002));
    assert_eq!(malformed(&unknown), ErrorCode::MalformedXML);
    let nested = format!("<Delete>{}</Delete>", "<a><b></b></a>".repeat(1001));
    assert_eq!(malformed(&nested), ErrorCode::MalformedXML);
    // The cap follows the caller's maximum.
    let three = format!(
        "<Delete>{}</Delete>",
        "<Object><Key>k</Key></Object>".repeat(3)
    );
    assert_eq!(
        parse_delete(three.as_bytes(), &policy(), 2).unwrap_err(),
        ErrorCode::MalformedXML
    );
    assert_eq!(
        parse_delete(three.as_bytes(), &policy(), 3)
            .unwrap()
            .keys
            .len(),
        3
    );
}

#[test]
fn a_delete_result_has_one_entry_per_key_in_request_order() {
    let keys = ["a".to_string(), "b & <c>".to_string(), "a".to_string()];
    let failed = DeleteOutcome::Failed {
        code: "InternalError",
        message: "We encountered an internal error. Please try again.",
    };
    let outcomes = [DeleteOutcome::Deleted, failed, DeleteOutcome::Deleted];

    let xml = text(&delete_result(&keys, &outcomes, false).unwrap());
    assert_eq!(
        xml,
        "<DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Deleted><Key>a</Key></Deleted>\
         <Error><Key>b &amp; &lt;c&gt;</Key><Code>InternalError</Code>\
         <Message>We encountered an internal error. Please try again.</Message></Error>\
         <Deleted><Key>a</Key></Deleted></DeleteResult>"
    );

    // Quiet: only what failed.
    let xml = text(&delete_result(&keys, &outcomes, true).unwrap());
    assert_eq!(values(&xml, "Key"), ["b &amp; &lt;c&gt;"]);
    assert!(!xml.contains("<Deleted>"));
    let xml = text(&delete_result(&keys[..1], &outcomes[..1], true).unwrap());
    assert!(xml.ends_with(
        "<DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></DeleteResult>"
    ));

    // An outcome for every key, or no document.
    assert_eq!(
        delete_result(&keys, &outcomes[..2], false).unwrap_err(),
        ErrorCode::InternalError
    );
}

// ---------------------------------------------------------------------------
// ListMultipartUploads
// ---------------------------------------------------------------------------

fn upload(key: &str, id: &str) -> UploadEntry {
    UploadEntry {
        key: key.to_string(),
        upload_id: id.to_string(),
        initiated_ms: T0,
    }
}

/// Every upload of `rows` (sorted by key and id) that the page asks for
/// next, `batch` at a time, as a catalogue would answer.
fn run(mut page: ListUploads, rows: &[UploadEntry], batch: usize) -> String {
    let mut exhausted = false;
    while page.wants_more() {
        let got: Vec<UploadEntry> = rows
            .iter()
            .filter(|r| r.key.starts_with(page.prefix()))
            .filter(|r| match page.after() {
                None => true,
                Some((key, id)) => {
                    r.key.as_str() > key
                        || (r.key == key && id.is_some_and(|id| r.upload_id.as_str() > id))
                }
            })
            .filter(|r| page.skip_prefix().is_none_or(|p| !r.key.starts_with(p)))
            .take(batch)
            .cloned()
            .collect();
        let short = got.len() < batch;
        for row in got {
            if !page.wants_more() {
                break;
            }
            page.push(row).unwrap();
        }
        if short {
            exhausted = true;
            break;
        }
    }
    text(&page.finish(exhausted).unwrap())
}

fn rows() -> Vec<UploadEntry> {
    vec![
        upload("a.txt", "01"),
        upload("a.txt", "02"),
        upload("dir/one", "03"),
        upload("dir/two", "04"),
        upload("dir/two", "05"),
        upload("e/deep/x", "06"),
        upload("z", "07"),
    ]
}

#[test]
fn uploads_list_by_key_and_id_with_the_fields_of_the_request() {
    let xml = run(
        ListUploads::parse(&target("/bkt?uploads")).unwrap(),
        &rows(),
        3,
    );
    assert!(xml.starts_with(
        "<ListMultipartUploadsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Bucket>bkt</Bucket><KeyMarker></KeyMarker><UploadIdMarker></UploadIdMarker>\
         <Prefix></Prefix><MaxUploads>1000</MaxUploads><IsTruncated>false</IsTruncated>\
         <Upload><Key>a.txt</Key><UploadId>01</UploadId><StorageClass>STANDARD</StorageClass>\
         <Initiated>2026-11-13T00:00:00.000Z</Initiated></Upload>"
    ));
    assert_eq!(
        values(&xml, "UploadId"),
        ["01", "02", "03", "04", "05", "06", "07"]
    );
    assert!(!xml.contains("NextKeyMarker") && !xml.contains("CommonPrefixes"));

    // A prefix narrows the listing and is echoed.
    let xml = run(
        ListUploads::parse(&target("/bkt?uploads&prefix=dir%2F")).unwrap(),
        &rows(),
        2,
    );
    assert_eq!(values(&xml, "UploadId"), ["03", "04", "05"]);
    assert!(xml.contains("<Prefix>dir/</Prefix>"));
}

#[test]
fn a_delimiter_folds_keys_into_common_prefixes() {
    let xml = run(
        ListUploads::parse(&target("/bkt?uploads&delimiter=%2F")).unwrap(),
        &rows(),
        2,
    );
    assert_eq!(values(&xml, "UploadId"), ["01", "02", "07"]);
    assert!(xml.contains("<Delimiter>/</Delimiter>"));
    assert!(xml.contains(
        "<CommonPrefixes><Prefix>dir/</Prefix></CommonPrefixes>\
         <CommonPrefixes><Prefix>e/</Prefix></CommonPrefixes>"
    ));

    // Under a prefix the fold starts after it.
    let xml = run(
        ListUploads::parse(&target("/bkt?uploads&delimiter=%2F&prefix=e%2F")).unwrap(),
        &rows(),
        2,
    );
    assert!(xml.contains("<CommonPrefixes><Prefix>e/deep/</Prefix></CommonPrefixes>"));
    assert!(values(&xml, "UploadId").is_empty());
}

/// Follows the markers of each page until the listing ends; returns the
/// upload ids and common prefixes of all pages, in order.
fn walk(query: &str, rows: &[UploadEntry], batch: usize) -> (Vec<String>, usize) {
    let mut seen = Vec::new();
    let mut marker = String::new();
    let mut pages = 0;
    loop {
        pages += 1;
        assert!(pages < 50, "the listing does not end");
        let page = ListUploads::parse(&target(&format!("/bkt?uploads{query}{marker}"))).unwrap();
        let xml = run(page, rows, batch);
        // Uploads and prefixes are rendered in one sequence.
        let mut rest = xml.as_str();
        while let Some(i) = rest
            .find("<Upload>")
            .into_iter()
            .chain(rest.find("<CommonPrefixes>"))
            .min()
        {
            rest = &rest[i..];
            if rest.starts_with("<Upload>") {
                seen.push(values(rest, "UploadId").remove(0));
                rest = &rest["<Upload>".len()..];
            } else {
                seen.push(values(rest, "Prefix").remove(0));
                rest = &rest["<CommonPrefixes>".len()..];
            }
        }
        if values(&xml, "IsTruncated") == ["false"] {
            assert!(!xml.contains("NextKeyMarker"));
            return (seen, pages);
        }
        let key = values(&xml, "NextKeyMarker").remove(0);
        let id = values(&xml, "NextUploadIdMarker").remove(0);
        marker = format!("&key-marker={}", key.replace('/', "%2F"));
        if !id.is_empty() {
            marker.push_str(&format!("&upload-id-marker={id}"));
        }
    }
}

#[test]
fn the_markers_of_a_truncated_page_continue_the_listing() {
    // Two uploads of one key are split across pages by the upload id.
    let page = ListUploads::parse(&target("/bkt?uploads&max-uploads=1")).unwrap();
    let xml = run(page, &rows(), 10);
    assert_eq!(values(&xml, "UploadId"), ["01"]);
    assert!(xml.contains(
        "<NextKeyMarker>a.txt</NextKeyMarker><NextUploadIdMarker>01</NextUploadIdMarker>"
    ));
    assert!(xml.contains("<MaxUploads>1</MaxUploads><IsTruncated>true</IsTruncated>"));
    let page = ListUploads::parse(&target(
        "/bkt?uploads&max-uploads=1&key-marker=a.txt&upload-id-marker=01",
    ))
    .unwrap();
    let xml = run(page, &rows(), 10);
    assert_eq!(values(&xml, "UploadId"), ["02"]);
    assert!(xml.contains("<KeyMarker>a.txt</KeyMarker><UploadIdMarker>01</UploadIdMarker>"));

    // Every page size and every batch size gives the whole listing once.
    let all = ["01", "02", "03", "04", "05", "06", "07"];
    let folded = ["01", "02", "dir/", "e/", "07"];
    for max in 1..=8 {
        for batch in 1..=4 {
            let (seen, pages) = walk(&format!("&max-uploads={max}"), &rows(), batch);
            assert_eq!(seen, all, "max {max} batch {batch}");
            assert_eq!(pages, all.len().div_ceil(max), "max {max} batch {batch}");
            let (seen, _) = walk(&format!("&max-uploads={max}&delimiter=%2F"), &rows(), batch);
            assert_eq!(seen, folded, "folded, max {max} batch {batch}");
        }
    }

    // A key marker without an upload id marker starts after every upload
    // of that key; an upload id marker alone is ignored.
    let page = ListUploads::parse(&target("/bkt?uploads&key-marker=a.txt")).unwrap();
    assert_eq!(page.after(), Some(("a.txt", None)));
    let xml = run(page, &rows(), 10);
    assert_eq!(values(&xml, "UploadId"), ["03", "04", "05", "06", "07"]);
    let page = ListUploads::parse(&target("/bkt?uploads&upload-id-marker=03")).unwrap();
    assert_eq!(page.after(), None);
    assert_eq!(values(&run(page, &rows(), 10), "UploadId").len(), 7);
}

/// A key marker names a group to skip only when it is a common prefix of
/// this listing: the prefix, then a part that ends at the first
/// delimiter. The prefix itself, or less than one delimiter after it,
/// names no group, and nothing under the prefix is left out.
#[test]
fn a_key_marker_skips_a_group_only_when_it_ends_at_the_first_delimiter() {
    let skip = |query: &str| {
        let page = ListUploads::parse(&target(&format!("/bkt?uploads{query}"))).unwrap();
        page.skip_prefix().map(str::to_owned)
    };
    for (query, skipped) in [
        // The marker is one group under the prefix.
        ("&delimiter=%2F&key-marker=dir%2F", Some("dir/")),
        (
            "&prefix=dir%2F&delimiter=%2F&key-marker=dir%2Fa%2F",
            Some("dir/a/"),
        ),
        ("&prefix=d&delimiter=--&key-marker=dir--", Some("dir--")),
        // The marker is the prefix itself.
        ("&prefix=dir%2F&delimiter=%2F&key-marker=dir%2F", None),
        ("&prefix=dir--&delimiter=--&key-marker=dir--", None),
        // Less than one delimiter follows the prefix.
        ("&prefix=dir&delimiter=--&key-marker=dir-", None),
        // A key, a deeper group, another prefix, no delimiter, or an
        // upload id marker beside it.
        ("&prefix=dir%2F&delimiter=%2F&key-marker=dir%2Fa", None),
        (
            "&prefix=dir%2F&delimiter=%2F&key-marker=dir%2Fa%2Fb%2F",
            None,
        ),
        ("&prefix=other%2F&delimiter=%2F&key-marker=dir%2Fa%2F", None),
        ("&prefix=dir%2F&key-marker=dir%2Fa%2F", None),
        (
            "&prefix=dir%2F&delimiter=%2F&key-marker=dir%2Fa%2F&upload-id-marker=01",
            None,
        ),
    ] {
        assert_eq!(skip(query).as_deref(), skipped, "{query}");
    }
}

#[test]
fn a_page_cut_short_by_the_caller_is_truncated_and_continues() {
    // The caller stops after two rows without reaching the end.
    let mut page = ListUploads::parse(&target("/bkt?uploads")).unwrap();
    for row in &rows()[..2] {
        page.push(row.clone()).unwrap();
    }
    let xml = text(&page.finish(false).unwrap());
    assert_eq!(values(&xml, "UploadId"), ["01", "02"]);
    assert!(xml.contains(
        "<NextKeyMarker>a.txt</NextKeyMarker><NextUploadIdMarker>02</NextUploadIdMarker>"
    ));
    assert!(xml.contains("<IsTruncated>true</IsTruncated>"));

    // A truncated page that read nothing would send the client in a loop.
    let page = ListUploads::parse(&target("/bkt?uploads")).unwrap();
    assert_eq!(page.finish(false).unwrap_err(), ErrorCode::InternalError);

    // Rows out of order, outside the prefix or past the page are a bug of
    // the caller, not a listing.
    let mut page = ListUploads::parse(&target("/bkt?uploads&prefix=dir%2F")).unwrap();
    assert_eq!(
        page.push(upload("z", "07")).unwrap_err(),
        ErrorCode::InternalError
    );
    page.push(upload("dir/two", "04")).unwrap();
    assert_eq!(
        page.push(upload("dir/one", "03")).unwrap_err(),
        ErrorCode::InternalError
    );
    assert_eq!(
        page.push(upload("dir/two", "04")).unwrap_err(),
        ErrorCode::InternalError
    );
}

#[test]
fn page_sizes_and_encodings_of_an_upload_listing() {
    // max-uploads=0 lists nothing and is not truncated.
    let page = ListUploads::parse(&target("/bkt?uploads&max-uploads=0")).unwrap();
    assert!(!page.wants_more());
    let xml = text(&page.finish(true).unwrap());
    assert!(xml.contains("<MaxUploads>0</MaxUploads><IsTruncated>false</IsTruncated>"));
    // More than the cap is the cap.
    let page = ListUploads::parse(&target("/bkt?uploads&max-uploads=5000")).unwrap();
    assert!(text(&page.finish(true).unwrap()).contains("<MaxUploads>1000</MaxUploads>"));

    for bad in [
        "/bkt?uploads&max-uploads=ten",
        "/bkt?uploads&max-uploads=-1",
        "/bkt?uploads&encoding-type=base64",
    ] {
        assert_eq!(
            ListUploads::parse(&target(bad)).unwrap_err(),
            ErrorCode::InvalidArgument,
            "{bad}"
        );
    }
    assert!(ListUploads::parse(&target("/bkt?uploads&prefix=a&prefix=b")).is_err());

    // Keys are percent-encoded on request, and escaped otherwise.
    let rows = [upload("a b&c/é", "01")];
    let xml = run(
        ListUploads::parse(&target("/bkt?uploads&encoding-type=url")).unwrap(),
        &rows,
        10,
    );
    assert!(xml.contains("<EncodingType>url</EncodingType>"));
    assert_eq!(values(&xml, "Key"), ["a%20b%26c%2F%C3%A9"]);
    let xml = run(
        ListUploads::parse(&target("/bkt?uploads")).unwrap(),
        &rows,
        10,
    );
    assert_eq!(values(&xml, "Key"), ["a b&amp;c/é"]);
}

// ---------------------------------------------------------------------------
// ListParts
// ---------------------------------------------------------------------------

fn parts(numbers: &[u16]) -> Vec<PartEntry> {
    numbers
        .iter()
        .map(|&n| PartEntry {
            part_number: n,
            size: 100 + u64::from(n),
            etag: format!("\"etag{n}\""),
            last_modified_ms: T0 + 1500,
        })
        .collect()
}

const ID: &str = "0123456789abcdef0123456789abcdef";

#[test]
fn parts_list_in_number_order_with_their_fields() {
    let list = ListParts::parse(&target(&format!("/bkt/dir/k?uploadId={ID}"))).unwrap();
    assert_eq!(
        list,
        ListParts {
            part_number_marker: 0,
            max_parts: 1000
        }
    );
    let xml = text(
        &list
            .respond("bkt", "dir/k & co", ID, &parts(&[1, 3]))
            .unwrap(),
    );
    assert_eq!(
        xml,
        format!(
            "<ListPartsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Bucket>bkt</Bucket><Key>dir/k &amp; co</Key><UploadId>{ID}</UploadId>\
             <PartNumberMarker>0</PartNumberMarker><MaxParts>1000</MaxParts>\
             <IsTruncated>false</IsTruncated>\
             <Part><PartNumber>1</PartNumber><LastModified>2026-11-13T00:00:01.500Z</LastModified>\
             <ETag>&quot;etag1&quot;</ETag><Size>101</Size></Part>\
             <Part><PartNumber>3</PartNumber><LastModified>2026-11-13T00:00:01.500Z</LastModified>\
             <ETag>&quot;etag3&quot;</ETag><Size>103</Size></Part>\
             <StorageClass>STANDARD</StorageClass></ListPartsResult>"
        )
    );

    // No part yet.
    let xml = text(&list.respond("bkt", "k", ID, &[]).unwrap());
    assert!(xml.contains("<IsTruncated>false</IsTruncated><StorageClass>"));
    // Parts out of order are a bug of the caller.
    assert_eq!(
        list.respond("bkt", "k", ID, &parts(&[2, 1])).unwrap_err(),
        ErrorCode::InternalError
    );
    assert_eq!(
        list.respond("bkt", "k", ID, &parts(&[2, 2])).unwrap_err(),
        ErrorCode::InternalError
    );
}

#[test]
fn the_part_number_marker_continues_a_truncated_page() {
    let all = parts(&[1, 2, 5, 9, 10]);
    let mut marker = 0;
    let mut seen = Vec::new();
    let mut pages = 0;
    loop {
        pages += 1;
        let list = ListParts::parse(&target(&format!(
            "/bkt/k?uploadId={ID}&max-parts=2&part-number-marker={marker}"
        )))
        .unwrap();
        let xml = text(&list.respond("bkt", "k", ID, &all).unwrap());
        assert!(xml.contains(&format!("<PartNumberMarker>{marker}</PartNumberMarker>")));
        seen.extend(values(&xml, "PartNumber"));
        if values(&xml, "IsTruncated") == ["false"] {
            assert!(!xml.contains("NextPartNumberMarker"));
            break;
        }
        marker = values(&xml, "NextPartNumberMarker")[0].parse().unwrap();
    }
    assert_eq!(seen, ["1", "2", "5", "9", "10"]);
    assert_eq!(pages, 3);

    // A page that ends exactly on the last part is not truncated.
    let list = ListParts::parse(&target(&format!("/bkt/k?uploadId={ID}&max-parts=5"))).unwrap();
    let xml = text(&list.respond("bkt", "k", ID, &all).unwrap());
    assert!(xml.contains("<MaxParts>5</MaxParts><IsTruncated>false</IsTruncated>"));
    // A marker past the last part lists nothing.
    let list = ListParts::parse(&target(&format!(
        "/bkt/k?uploadId={ID}&part-number-marker=10000"
    )))
    .unwrap();
    assert!(values(
        &text(&list.respond("bkt", "k", ID, &all).unwrap()),
        "PartNumber"
    )
    .is_empty());
    // max-parts=0 lists nothing and is not truncated; over the cap is the cap.
    let list = ListParts::parse(&target(&format!("/bkt/k?uploadId={ID}&max-parts=0"))).unwrap();
    let xml = text(&list.respond("bkt", "k", ID, &all).unwrap());
    assert!(xml.contains("<MaxParts>0</MaxParts><IsTruncated>false</IsTruncated><StorageClass>"));
    let list = ListParts::parse(&target(&format!("/bkt/k?uploadId={ID}&max-parts=99999"))).unwrap();
    assert_eq!(list.max_parts, 1000);

    for bad in ["max-parts=x", "part-number-marker=x", "max-parts=-3"] {
        assert_eq!(
            ListParts::parse(&target(&format!("/bkt/k?uploadId={ID}&{bad}"))).unwrap_err(),
            ErrorCode::InvalidArgument,
            "{bad}"
        );
    }
}
