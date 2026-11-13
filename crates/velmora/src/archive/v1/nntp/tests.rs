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
impl Script {
    fn new(incoming: Vec<u8>, outgoing: Rc<RefCell<Vec<u8>>>) -> Self {
        Self {
            incoming: Cursor::new(incoming),
            outgoing,
            started: Rc::new(tokio::sync::Notify::new()),
            shutdowns: Rc::new(Cell::new(0)),
            suspend: false,
        }
    }
}
async fn connect(transport: Script) -> NntpClient<Script> {
    NntpClient::connect_with_auth_guard(transport, &NntpConfig::default(), || Ok(()))
        .await
        .unwrap()
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
#[derive(Default)]
struct Revocation {
    failure: Cell<Option<Failure>>,
    part_checks: Cell<usize>,
    part_revoked: Cell<bool>,
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
            if self.part_revoked.get() {
                return Failure::Denied;
            }
            notified.await;
        }
    }
}
impl ReadControl for Revocation {
    fn check_part(&self, _: &Target, message_id: &str) -> Result<()> {
        let remaining = self.part_checks.get();
        self.part_checks.set(remaining.saturating_sub(1));
        if self.part_revoked.get()
            || remaining == 1
            || (message_id != "part@synthetic.invalid"
                && message_id != format!("{}@b", "x".repeat(248)))
        {
            return Err(Failure::Denied);
        }
        Ok(())
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
async fn interruption_returns_without_cleanup_and_poisons_stat() {
    for failure in [Failure::Cancelled, Failure::Deadline, Failure::Denied] {
        let outgoing = Rc::new(RefCell::new(Vec::new()));
        let mut transport = Script::new(b"200 ready\r\n200 reader\r\n".to_vec(), outgoing.clone());
        transport.suspend = true;
        let started = transport.started.clone();
        let shutdowns = transport.shutdowns.clone();
        let mut client = connect(transport).await;
        let control = Revocation::default();
        let target = target();
        {
            let operation = async {
                ClientIo::new(&mut client, &target.account)
                    .stat(&target, "part@synthetic.invalid", &control)
                    .await
            };
            tokio::pin!(operation);
            tokio::select! {
                started = tokio::time::timeout(std::time::Duration::from_secs(1), started.notified()) => { started.unwrap(); },
                result = &mut operation => panic!("operation did not suspend: {result:?}"),
            }
            struct WakeCount(std::sync::atomic::AtomicUsize);
            impl std::task::Wake for WakeCount {
                fn wake(self: std::sync::Arc<Self>) {
                    self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
            let wakes = std::sync::Arc::new(WakeCount(std::sync::atomic::AtomicUsize::new(0)));
            let waker = std::task::Waker::from(wakes.clone());
            let mut cx = std::task::Context::from_waker(&waker);
            assert!(operation.as_mut().poll(&mut cx).is_pending());
            if failure == Failure::Denied {
                control.part_revoked.set(true);
                assert_eq!(control.check(&target, Action::Read), Ok(()));
            } else {
                control.failure.set(Some(failure));
            }
            control.notify.notify_waiters();
            assert!(wakes.0.load(std::sync::atomic::Ordering::SeqCst) > 0);
            let result = tokio::time::timeout(std::time::Duration::from_secs(1), operation)
                .await
                .unwrap();
            assert_eq!(result, Err(failure));
        }
        assert_eq!(shutdowns.get(), 0);
        let sent = outgoing.borrow().len();
        assert!(client.stat("part@synthetic.invalid").await.is_err());
        assert_eq!(outgoing.borrow().len(), sent);
        assert!(!outgoing.borrow().windows(4).any(|bytes| bytes == b"QUIT"));
    }
}
#[tokio::test]
async fn bad_replies_poison_stat_session() {
    for (reply, expected, revoke) in [
        (b"invalid\r\n".as_slice(), Failure::Integrity, false),
        (b"220 unexpected\r\n".as_slice(), Failure::Integrity, false),
        (b"430 missing\r\n".as_slice(), Failure::Denied, true),
    ] {
        let outgoing = Rc::new(RefCell::new(Vec::new()));
        let mut incoming = b"200 ready\r\n200 reader\r\n".to_vec();
        incoming.extend_from_slice(reply);
        incoming.extend_from_slice(b"223 1 <part@synthetic.invalid>\r\n.\r\n");
        let mut client = connect(Script::new(incoming, outgoing.clone())).await;
        let control = Revocation::default();
        if revoke {
            control.part_checks.set(2);
        }
        let target = target();
        let mut io = ClientIo::new(&mut client, &target.account);
        assert_eq!(
            io.stat(&target, "part@synthetic.invalid", &control).await,
            Err(expected)
        );
        let sent = outgoing.borrow().len();
        assert!(client.stat("part@synthetic.invalid").await.is_err());
        assert_eq!(outgoing.borrow().len(), sent);
    }
}

#[tokio::test]
async fn stat_checks_binding_and_classifies_oversized_reply() {
    let unrelated = io::Error::new(io::ErrorKind::InvalidData, "NNTP line exceeds 16 KiB");
    assert!(!crate::transport::is_line_limit_error(&unrelated));
    let max_id = format!("{}@b", "x".repeat(248));
    let mut incoming = format!("200 ready\r\n200 reader\r\n223 1 <{max_id}>\r\n223 ").into_bytes();
    incoming.extend(std::iter::repeat_n(b'x', crate::transport::MAX_LINE_BYTES));
    incoming.extend_from_slice(b"\r\n");
    let outgoing = Rc::new(RefCell::new(Vec::new()));
    let transport = Script::new(incoming, outgoing.clone());
    let mut client = connect(transport).await;
    let target = target();
    let control = Revocation::default();
    let mut io = ClientIo::new(&mut client, &target.account);
    let sent = outgoing.borrow().len();
    let mut wrong_account = target.clone();
    wrong_account.account = Id::new("other").unwrap();
    let mut wrong_backend = target.clone();
    wrong_backend.backend = Backend::S3;
    for wrong in [&wrong_account, &wrong_backend] {
        assert_eq!(
            io.stat(wrong, "part@synthetic.invalid", &control).await,
            Err(Failure::Denied)
        );
    }
    assert_eq!(
        io.stat(&target, "other@synthetic.invalid", &control).await,
        Err(Failure::Denied)
    );
    let too_long = format!("x{max_id}");
    for invalid in [
        "", &too_long, "missing", "a@@b", "@b", "a@", "é@b", "a@b\r\n",
    ] {
        assert_eq!(
            io.stat(&target, invalid, &control).await,
            Err(Failure::Invalid)
        );
    }
    assert_eq!(outgoing.borrow().len(), sent);
    assert_eq!(io.stat(&target, &max_id, &control).await, Ok(()));
    assert_eq!(outgoing.borrow().len() - sent, 259);
    assert_eq!(
        io.stat(&target, "part@synthetic.invalid", &control).await,
        Err(Failure::Limit)
    );
    let sent = outgoing.borrow().len();
    assert!(client.stat("part@synthetic.invalid").await.is_err());
    assert_eq!(outgoing.borrow().len(), sent);
}
