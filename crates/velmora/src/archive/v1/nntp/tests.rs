use super::*;
use crate::{archive::v1::EncryptionIdentity, nntp::NntpConfig};
use std::{
    cell::{Cell, RefCell},
    io::{self, Cursor, Read},
    rc::Rc,
};

struct Script {
    incoming: Cursor<Vec<u8>>,
    outgoing: Rc<RefCell<Vec<u8>>>,
    started: Rc<tokio::sync::Notify>,
    shutdowns: Rc<Cell<usize>>,
    suspend: bool,
}
impl Transport for Script {
    async fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.suspend && self.incoming.position() == self.incoming.get_ref().len() as u64 {
            self.started.notify_one();
            std::future::pending().await
        } else {
            self.incoming.read(out)
        }
    }
    async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.outgoing.borrow_mut().extend_from_slice(bytes);
        Ok(())
    }
    async fn shutdown(&mut self) -> io::Result<()> {
        self.shutdowns.set(self.shutdowns.get() + 1);
        std::future::pending().await
    }
}

struct Revocation {
    failure: Cell<Option<Failure>>,
    notify: tokio::sync::Notify,
}
impl Control for Revocation {
    fn check(&self, _: &Target, _: Action) -> Result<()> {
        self.failure.get().map_or(Ok(()), Err)
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

fn target() -> Target {
    let id = || Id::new("synthetic").unwrap();
    Target {
        tenant: id(),
        backend: Backend::Nntp,
        account: id(),
        locator: id(),
        generation: id(),
        encryption: EncryptionIdentity {
            format: id(),
            mode: 1,
            key_epoch: id(),
            envelope: id(),
        },
    }
}

#[tokio::test]
async fn interruption_returns_without_cleanup_and_poisons_each_command() {
    for failure in [Failure::Cancelled, Failure::Deadline] {
        for phase in 0..4 {
            let started = Rc::new(tokio::sync::Notify::new());
            let shutdowns = Rc::new(Cell::new(0));
            let outgoing = Rc::new(RefCell::new(Vec::new()));
            let mut incoming = b"200 ready\r\n200 reader\r\n".to_vec();
            if phase == 1 {
                incoming.extend_from_slice(b"340 send\r\n");
            }
            let transport = Script {
                incoming: Cursor::new(incoming),
                outgoing: outgoing.clone(),
                started: started.clone(),
                shutdowns: shutdowns.clone(),
                suspend: true,
            };
            let mut client =
                NntpClient::connect_with_auth_guard(transport, &NntpConfig::default(), || Ok(()))
                    .await
                    .unwrap();
            let control = Revocation {
                failure: Cell::new(None),
                notify: tokio::sync::Notify::new(),
            };
            let target = target();
            {
                let operation = async {
                    let mut io = ClientIo {
                        client: &mut client,
                    };
                    match phase {
                        0 | 1 => {
                            io.post(
                                &target,
                                "part@synthetic.invalid",
                                b"synthetic\r\n",
                                &control,
                            )
                            .await
                        }
                        2 => io
                            .body(&target, "part@synthetic.invalid", &control)
                            .await
                            .map(|_| ()),
                        _ => io.stat(&target, "part@synthetic.invalid", &control).await,
                    }
                };
                tokio::pin!(operation);
                tokio::select! {
                    _ = started.notified() => {},
                    result = &mut operation => panic!("operation did not suspend: {result:?}"),
                }
                control.failure.set(Some(failure));
                control.notify.notify_waiters();
                let result = tokio::time::timeout(std::time::Duration::from_secs(1), operation)
                    .await
                    .unwrap();
                assert_eq!(
                    result,
                    Err(if phase < 2 {
                        Failure::Uncertain
                    } else {
                        failure
                    })
                );
            }
            assert_eq!(shutdowns.get(), 0);
            let sent = outgoing.borrow().len();
            assert!(client.stat("part@synthetic.invalid").await.is_err());
            assert_eq!(outgoing.borrow().len(), sent);
            assert!(!outgoing.borrow().windows(4).any(|bytes| bytes == b"QUIT"));
        }
    }
}

#[tokio::test]
async fn article_cap_is_forwarded_and_classified_as_limit() {
    let mut incoming = b"200 ready\r\n200 reader\r\n222 1 <part@synthetic.invalid>\r\n".to_vec();
    incoming.extend(std::iter::repeat_n(b'x', 129));
    incoming.extend_from_slice(b"\r\n.\r\n");
    let transport = Script {
        incoming: Cursor::new(incoming),
        outgoing: Rc::new(RefCell::new(Vec::new())),
        started: Rc::new(tokio::sync::Notify::new()),
        shutdowns: Rc::new(Cell::new(0)),
        suspend: false,
    };
    let config = NntpConfig {
        max_article_bytes: 64,
        ..Default::default()
    };
    let mut client = NntpClient::connect_with_auth_guard(transport, &config, || Ok(()))
        .await
        .unwrap();
    let mut io = ClientIo {
        client: &mut client,
    };
    assert_eq!(io.max_encoded_body_bytes(), Some(64));
    let control = Revocation {
        failure: Cell::new(None),
        notify: tokio::sync::Notify::new(),
    };
    assert_eq!(
        io.body(&target(), "part@synthetic.invalid", &control).await,
        Err(Failure::Limit)
    );
}
