use std::io;
use std::sync::{Arc, Mutex};

use nntune_core::nntp::{NntpClient, NntpConfig};
use nntune_core::transport::Transport;

#[derive(Default)]
pub struct Trace {
    pub written: Vec<u8>,
    pub shutdown: bool,
}

pub struct Script {
    replies: Vec<u8>,
    offset: usize,
    chunk: usize,
    trace: Arc<Mutex<Trace>>,
}

impl Transport for Script {
    async fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.trace.lock().unwrap().shutdown {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "closed"));
        }
        let n = out
            .len()
            .min(self.chunk)
            .min(self.replies.len() - self.offset);
        out[..n].copy_from_slice(&self.replies[self.offset..self.offset + n]);
        self.offset += n;
        Ok(n)
    }

    async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        let mut trace = self.trace.lock().unwrap();
        if trace.shutdown {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "closed"));
        }
        trace.written.extend_from_slice(bytes);
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.trace.lock().unwrap().shutdown = true;
        Ok(())
    }
}

pub async fn connect(
    replies: &[u8],
    chunk: usize,
    config: &NntpConfig,
) -> (NntpClient<Script>, Arc<Mutex<Trace>>) {
    let trace = Arc::new(Mutex::new(Trace::default()));
    let mut wire = b"200 ready\r\n200 reader mode\r\n".to_vec();
    wire.extend_from_slice(replies);
    let script = Script {
        replies: wire,
        offset: 0,
        chunk,
        trace: trace.clone(),
    };
    let client = NntpClient::connect(script, config)
        .await
        .expect("handshake");
    (client, trace)
}
