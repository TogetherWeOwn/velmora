//! Concrete [`crate::transport::Transport`] implementations.
//!
//! - [`tokio_tls`] (feature `native-tls`, non-wasm targets): TCP +
//!   rustls TLS over tokio, with per-operation timeouts via
//!   [`tokio::time::timeout`].
//! - [`worker_socket`] (feature `worker-transport`, wasm32 only): the
//!   Workers [`connect()`](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/)
//!   TCP socket, with per-operation timeouts via
//!   [`worker::Delay`](https://docs.rs/worker).
//! - [`worker_socks5`] (feature `worker-socks5-tls`, wasm32 only): that socket through a
//!   SOCKS5 proxy, with TLS end to end from the Worker to the provider.

#[cfg(any(
    feature = "native-tls",
    feature = "worker-pinned-tls",
    feature = "worker-socks5-tls"
))]
pub mod peer_tls;

#[cfg(all(feature = "worker-pinned-tls", target_arch = "wasm32"))]
pub mod worker_pinned_tls;

#[cfg(all(feature = "native-tls", not(target_arch = "wasm32")))]
pub mod tokio_tls;

#[cfg(all(feature = "native-tls", not(target_arch = "wasm32")))]
pub use tokio_tls::{
    connect as connect_native, connect_pinned as connect_native_pinned, NativeTlsTransport,
};

// Runtime-free, so its tests run natively; the Workers stream is its
// only user outside them.
#[cfg(any(test, all(feature = "worker-transport", target_arch = "wasm32")))]
mod chunk_reader;

#[cfg(all(feature = "worker-transport", target_arch = "wasm32"))]
pub mod worker_socket;

#[cfg(all(feature = "worker-transport", target_arch = "wasm32"))]
mod worker_stream;

#[cfg(all(feature = "worker-transport", target_arch = "wasm32"))]
pub use worker_socket::WorkerTransport;

#[cfg(any(feature = "native-tls", feature = "worker-socks5-tls"))]
pub mod proxy_tls;

#[cfg(all(feature = "worker-socks5-tls", target_arch = "wasm32"))]
pub mod worker_socks5;

#[cfg(all(feature = "worker-socks5-tls", target_arch = "wasm32"))]
pub use worker_socks5::WorkerProxiedTransport;
