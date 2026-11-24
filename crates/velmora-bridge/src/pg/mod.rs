//! Postgres implementation of the catalogue SQL port.

mod params;
#[cfg(test)]
mod tests;

use crate::Result;

/// One catalogue connection owned by the calling request. Dropping it stops
/// the corresponding connection driver, even if the request was cancelled.
pub struct PgConnection {
    client: tokio_postgres::Client,
    close: Option<Box<dyn FnOnce()>>,
}

impl PgConnection {
    pub fn new(client: tokio_postgres::Client, close: impl FnOnce() + 'static) -> Self {
        Self {
            client,
            close: Some(Box::new(close)),
        }
    }

    pub fn client(&self) -> &tokio_postgres::Client {
        &self.client
    }
}

impl Drop for PgConnection {
    fn drop(&mut self) {
        if let Some(close) = self.close.take() {
            close();
        }
    }
}

/// A runtime-specific factory, not a pool or an open socket.
#[allow(async_fn_in_trait)]
pub trait PgConnect {
    async fn connect(&self) -> Result<PgConnection>;
}

#[derive(Clone, Copy, Debug)]
pub struct PgConfig {
    pub lock_key: i64,
    pub pipeline: bool,
}

impl Default for PgConfig {
    fn default() -> Self {
        Self {
            lock_key: 7_413_000_001,
            pipeline: true,
        }
    }
}

/// Accepts a write and a read connector. The backend itself never owns a
/// connection, so it is safe to share across Worker I/O contexts.
#[allow(dead_code)]
pub struct PgSql<C: PgConnect> {
    writer: C,
    reader: C,
    config: PgConfig,
}

impl<C: PgConnect> PgSql<C> {
    pub fn new(writer: C, reader: C, config: PgConfig) -> Self {
        Self {
            writer,
            reader,
            config,
        }
    }
}
