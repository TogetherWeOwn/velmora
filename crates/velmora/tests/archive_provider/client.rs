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

#[tokio::test]
async fn configured_article_cap_is_a_limit_not_retry_permission() {
    use nntp::Io;
    let (intent, _) = intent(Backend::Nntp, &[13]);
    let reference = intent.parts[0].reference.as_str();
    let mut incoming = format!("200 ready\r\n200 reader\r\n222 1 <{reference}>\r\n").into_bytes();
    incoming.extend(std::iter::repeat_n(b'x', 129));
    incoming.extend_from_slice(b"\r\n.\r\n");
    let transport = Script {
        incoming: Cursor::new(incoming),
        outgoing: Rc::new(RefCell::new(Vec::new())),
    };
    let config = NntpConfig {
        max_article_bytes: 64,
        ..Default::default()
    };
    let mut client = NntpClient::connect_with_auth_guard(transport, &config, || Ok(()))
        .await
        .unwrap();
    let mut io = nntp::ClientIo {
        client: &mut client,
    };
    assert_eq!(
        io.body(&intent.target, reference, &Authority::new()).await,
        Err(Failure::Limit)
    );
}

struct Revocation {
    authority: Authority,
    notify: tokio::sync::Notify,
}
impl Control for Revocation {
    fn check(&self, target: &Target, action: Action) -> Result<()> {
        self.authority.check(target, action)
    }

    async fn cancelled(&self, target: &Target, action: Action) -> Failure {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Err(error) = self.check(target, action) {
                return error;
            }
            notified.await;
        }
    }
}

struct Suspended {
    incoming: Cursor<Vec<u8>>,
    outgoing: Rc<RefCell<Vec<u8>>>,
    started: Rc<tokio::sync::Notify>,
    shutdowns: Rc<Cell<usize>>,
}
impl Transport for Suspended {
    async fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.incoming.position() < self.incoming.get_ref().len() as u64 {
            return self.incoming.read(out);
        }
        self.started.notify_one();
        std::future::pending().await
    }
    async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.outgoing.borrow_mut().extend_from_slice(bytes);
        Ok(())
    }
    async fn shutdown(&mut self) -> io::Result<()> {
        self.shutdowns.set(self.shutdowns.get() + 1);
        Ok(())
    }
}

#[tokio::test]
async fn invocation_revocation_interrupts_pending_post_body_and_stat_and_closes() {
    use nntp::Io;
    for phase in 0..4 {
        let (intent, _) = intent(Backend::Nntp, &[13]);
        let started = Rc::new(tokio::sync::Notify::new());
        let shutdowns = Rc::new(Cell::new(0));
        let outgoing = Rc::new(RefCell::new(Vec::new()));
        let mut incoming = b"200 ready\r\n200 reader\r\n".to_vec();
        if phase == 1 {
            incoming.extend_from_slice(b"340 send\r\n");
        }
        let transport = Suspended {
            incoming: Cursor::new(incoming),
            outgoing: outgoing.clone(),
            started: started.clone(),
            shutdowns: shutdowns.clone(),
        };
        let mut client =
            NntpClient::connect_with_auth_guard(transport, &NntpConfig::default(), || Ok(()))
                .await
                .unwrap();
        let control = Revocation {
            authority: Authority::new(),
            notify: tokio::sync::Notify::new(),
        };
        {
            let operation = async {
                let mut io = nntp::ClientIo {
                    client: &mut client,
                };
                let reference = intent.parts[0].reference.as_str();
                match phase {
                    0 | 1 => {
                        io.post(&intent.target, reference, b"synthetic\r\n", &control)
                            .await
                    }
                    2 => io
                        .body(&intent.target, reference, &control)
                        .await
                        .map(|_| ()),
                    _ => io.stat(&intent.target, reference, &control).await,
                }
            };
            tokio::pin!(operation);
            tokio::select! {
                _ = started.notified() => {},
                result = &mut operation => panic!("operation did not suspend: {result:?}"),
            }
            control.authority.state.set(Some(Failure::Cancelled));
            control.notify.notify_waiters();
            let result = tokio::time::timeout(std::time::Duration::from_secs(1), operation)
                .await
                .unwrap();
            assert_eq!(
                result,
                Err(if phase < 2 {
                    Failure::Uncertain
                } else {
                    Failure::Cancelled
                })
            );
        }
        assert_eq!(shutdowns.get(), 1);
        let sent = outgoing.borrow().len();
        assert!(client
            .stat(intent.parts[0].reference.as_str())
            .await
            .is_err());
        assert_eq!(outgoing.borrow().len(), sent);
        assert!(!outgoing.borrow().windows(4).any(|bytes| bytes == b"QUIT"));
    }
}
