//! Model close evidence separately from shutdown and transport destruction.
use std::{
    cell::{Cell, RefCell},
    io::{self, Cursor, Read},
    rc::Rc,
};
use velmora::{
    nntp::{NntpClient, NntpConfig},
    transport::Transport,
};

#[derive(Clone, Copy)]
enum ShutdownOutcome {
    Success,
    Failure,
    Pending,
}

#[derive(Default)]
struct CloseEvidence {
    requests: Cell<usize>,
    shutdowns_started: Cell<usize>,
    shutdowns_completed: Cell<usize>,
    destroyed: Cell<bool>,
    confirmed: Cell<bool>,
}
impl CloseEvidence {
    fn confirm(&self, result: io::Result<()>) -> io::Result<()> {
        result?;
        self.confirmed.set(true);
        Ok(())
    }
}

struct HalfClose {
    incoming: Cursor<Vec<u8>>,
    outgoing: Rc<RefCell<Vec<u8>>>,
    outcome: ShutdownOutcome,
    close: Rc<CloseEvidence>,
}
impl Transport for HalfClose {
    async fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.incoming.read(out)
    }
    async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.outgoing.borrow_mut().extend_from_slice(bytes);
        Ok(())
    }
    async fn shutdown(&mut self) -> io::Result<()> {
        self.close.requests.set(self.close.requests.get() + 1);
        self.close
            .shutdowns_started
            .set(self.close.shutdowns_started.get() + 1);
        let result = match self.outcome {
            // A completed write-half shutdown is not full socket closure.
            ShutdownOutcome::Success => Ok(()),
            ShutdownOutcome::Failure => Err(io::Error::other("synthetic shutdown failure")),
            ShutdownOutcome::Pending => std::future::pending().await,
        };
        self.close
            .shutdowns_completed
            .set(self.close.shutdowns_completed.get() + 1);
        result
    }
}
impl Drop for HalfClose {
    fn drop(&mut self) {
        // Drop requests but cannot confirm closure; the control outlives it.
        self.close.requests.set(self.close.requests.get() + 1);
        self.close.destroyed.set(true);
    }
}

#[tokio::test]
async fn shutdown_and_destruction_do_not_replace_independent_close_confirmation() {
    for outcome in [
        ShutdownOutcome::Success,
        ShutdownOutcome::Failure,
        ShutdownOutcome::Pending,
    ] {
        let outgoing = Rc::new(RefCell::new(Vec::new()));
        let close = Rc::new(CloseEvidence::default());
        let transport = HalfClose {
            incoming: Cursor::new(b"200 ready\r\n200 reader\r\n".to_vec()),
            outgoing: outgoing.clone(),
            outcome,
            close: close.clone(),
        };
        let mut client =
            NntpClient::connect_with_auth_guard(transport, &NntpConfig::default(), || Ok(()))
                .await
                .unwrap();
        match outcome {
            ShutdownOutcome::Success => client.shutdown_unusable().await.unwrap(),
            ShutdownOutcome::Failure => assert!(client.shutdown_unusable().await.is_err()),
            ShutdownOutcome::Pending => {
                let shutdown = client.shutdown_unusable();
                tokio::pin!(shutdown);
                std::future::poll_fn(|cx| {
                    assert!(std::future::Future::poll(shutdown.as_mut(), cx).is_pending());
                    std::task::Poll::Ready(())
                })
                .await;
                // Drop the polled shutdown future without completing it.
            }
        }
        assert_eq!(close.shutdowns_started.get(), 1);
        assert_eq!(
            close.shutdowns_completed.get(),
            usize::from(!matches!(outcome, ShutdownOutcome::Pending))
        );
        assert_eq!(close.requests.get(), 1);
        assert!(!close.confirmed.get());
        let sent = outgoing.borrow().len();
        assert!(client.stat("generated@test").await.is_err());
        assert_eq!(outgoing.borrow().len(), sent);
        assert!(!close.destroyed.get());
        drop(client);
        assert!(close.destroyed.get());
        assert_eq!(close.requests.get(), 2);
        assert!(
            !close.confirmed.get(),
            "destruction is only a close request"
        );
        // Model external confirmation, not a live Worker socket or pool.
        assert!(close
            .confirm(Err(io::Error::other("close failed")))
            .is_err());
        assert!(
            !close.confirmed.get(),
            "failed confirmation retains the charge"
        );
        close.confirm(Ok(())).unwrap();
        assert!(close.confirmed.get());
    }
}
