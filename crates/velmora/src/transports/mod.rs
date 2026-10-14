//! Concrete [`crate::transport::Transport`] implementations.
//!
//! - [`tokio_tls`] (feature `native-tls`, non-wasm targets): TCP +
//!   rustls TLS over tokio, with per-operation timeouts via
//!   [`tokio::time::timeout`].
//! - [`worker_socket`] (feature `worker-transport`, wasm32 only): the
//!   Workers [`connect()`](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/)
//!   TCP socket, with per-operation timeouts via
//!   [`worker::Delay`](https://docs.rs/worker).

#[cfg(all(feature = "native-tls", not(target_arch = "wasm32")))]
pub mod tokio_tls;

#[cfg(all(feature = "native-tls", not(target_arch = "wasm32")))]
pub use tokio_tls::{connect as connect_native, NativeTlsTransport};

#[cfg(all(feature = "worker-transport", target_arch = "wasm32"))]
pub mod worker_socket;

#[cfg(all(feature = "worker-transport", target_arch = "wasm32"))]
pub use worker_socket::WorkerTransport;
