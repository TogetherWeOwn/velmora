//! Request-local connections over a Hyperdrive binding. This adapter never
//! stores a Worker socket, client, driver, or parsed credentials.

use futures_channel::oneshot;
use futures_util::future::abortable;
use tokio_postgres::Config;
use velmora_bridge::pg::{classify_connect_error, PgConnect, PgConnection};
use velmora_bridge::{BridgeError, Result};
use worker::{
    postgres_tls::PassthroughTls, wasm_bindgen_futures::spawn_local, Hyperdrive, SecureTransport,
    Socket,
};

pub struct HyperdriveConnect(Hyperdrive);

impl HyperdriveConnect {
    pub fn new(binding: Hyperdrive) -> Self {
        Self(binding)
    }
}

impl PgConnect for HyperdriveConnect {
    async fn connect(&self) -> Result<PgConnection> {
        let config: Config = self.0.connection_string().parse().map_err(|_| failed())?;
        let socket = Socket::builder()
            .secure_transport(SecureTransport::StartTls)
            .connect(self.0.host(), self.0.port())
            .map_err(|_| failed())?;
        let (client, connection) = config
            .connect_raw(socket, PassthroughTls)
            .await
            .map_err(classify_connect_error)?;
        let (closed, done) = oneshot::channel();
        let (driver, stop) = abortable(connection);
        // The driver belongs to this client's I/O context. On normal exit,
        // closing the client makes it send Terminate and shut down its socket.
        // On cancellation, abort it rather than leaving it in the isolate.
        spawn_local(async move {
            let _ = driver.await;
            let _ = closed.send(());
        });
        Ok(
            PgConnection::new(client, move || stop.abort()).with_shutdown(async move {
                let _ = done.await;
            }),
        )
    }
}

fn failed() -> BridgeError {
    // Neither driver nor Cloudflare errors can be logged here: they can
    // contain the database configuration or server message text.
    BridgeError::Sql("pg: statement failed".into())
}
