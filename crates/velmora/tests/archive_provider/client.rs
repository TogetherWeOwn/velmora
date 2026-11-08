use super::*;
use std::{
    cell::RefCell,
    io::{self, Cursor, Read},
};
use velmora::{
    nntp::{NntpClient, NntpConfig},
    transport::Transport,
    yenc,
};

struct Script {
    incoming: Cursor<Vec<u8>>,
    outgoing: Rc<RefCell<Vec<u8>>>,
}
impl Transport for Script {
    async fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.incoming.read(out)
    }
    async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.outgoing.borrow_mut().extend_from_slice(bytes);
        Ok(())
    }
    async fn shutdown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn adapter_executes_existing_client_post_and_body_without_new_pool_or_dial() {
    let (intent, bytes) = intent(Backend::Nntp, &[137]);
    let reference = intent.parts[0].reference.as_str();
    let mut body = Vec::new();
    yenc::encode_segment(&mut body, &yenc::SegmentParams::single("synthetic"), &bytes).unwrap();
    let mut incoming =
        format!("200 ready\r\n200 reader\r\n340 send\r\n240 accepted\r\n222 1 <{reference}>\r\n")
            .into_bytes();
    for line in body.split_inclusive(|byte| *byte == b'\n') {
        if line.starts_with(b".") {
            incoming.push(b'.');
        }
        incoming.extend_from_slice(line);
    }
    incoming.extend_from_slice(b".\r\n");
    let outgoing = Rc::new(RefCell::new(Vec::new()));
    let transport = Script {
        incoming: Cursor::new(incoming),
        outgoing: outgoing.clone(),
    };
    let config = NntpConfig {
        max_article_bytes: 4096,
        ..Default::default()
    };
    let mut client = NntpClient::connect_with_auth_guard(transport, &config, || Ok(()))
        .await
        .unwrap();
    let io = nntp::ClientIo {
        client: &mut client,
    };
    let mut provider = nntp::Provider::new(id("account-a"), io, Some(posting(&intent)));
    let authority = Authority::new();
    let (session, receipts) = upload(&mut provider, &intent, &bytes, &authority).await;
    let proof = provider
        .commit(&session, &receipts, &authority)
        .await
        .unwrap();
    assert!(proof.full_ciphertext_readback);
    let wire = outgoing.borrow();
    assert!(wire.starts_with(b"MODE READER\r\nPOST\r\n"));
    assert!(wire.ends_with(format!("BODY <{reference}>\r\n").as_bytes()));
    assert!(wire
        .windows(b"=ybegin".len())
        .any(|window| window == b"=ybegin"));
}
