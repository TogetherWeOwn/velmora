//! The Workers `connect()` socket as one byte stream, with few calls into
//! the runtime.
//!
//! `worker::Socket` takes a stream reader for each read and gives it back
//! after (`getReader`, `read`, `releaseLock`), and takes a chunk of
//! whatever size the runtime hands over. On an article body that is
//! hundreds of calls into the runtime for each MiB, and they cost about
//! as much processor time as hashing the bytes.
//!
//! [`WorkerStream`] takes one reader and one writer when the connection
//! opens and keeps them for its life. Where the runtime's stream takes
//! reads into a caller's buffer (a "bring your own buffer" reader) it
//! asks for up to [`READ_BUFFER_BYTES`] in one read, into one buffer that
//! is used again for the next; otherwise it reads chunks as the runtime
//! hands them over. Either way the bytes are the same bytes in the same
//! order ([`super::chunk_reader`], tested natively), and a chunk is
//! copied once, into the caller's buffer.
//!
//! What does not change:
//! - A read or write in flight belongs to the stream, not to the future
//!   that started it. A caller that gives up (a timeout) loses nothing
//!   the runtime handed over; the next read picks the same read up.
//! - A write is done when the runtime's write promise settles, and a
//!   shutdown first waits for the write in flight, then closes the
//!   writable side.
//! - Dropping the stream asks the runtime to close the socket. The
//!   runtime closes a socket whose streams are held by a reader and a
//!   writer; the end-to-end run counts connections at the server.

#![cfg(all(feature = "worker-transport", target_arch = "wasm32"))]

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use worker::js_sys::{ArrayBuffer, Error as JsError, Object, Promise, Reflect, Uint8Array};
use worker::wasm_bindgen::prelude::wasm_bindgen;
use worker::wasm_bindgen::{JsCast, JsValue};
use worker::wasm_bindgen_futures::JsFuture;
use worker::worker_sys;

use super::chunk_reader::{ChunkPort, ChunkReader};

/// The most one read asks the runtime for, and the size of the buffer
/// that is used again from read to read. It is the size of the client's
/// own read buffer (`transport::READ_CHUNK_BYTES`), so one read here
/// fills one read there.
pub(super) const READ_BUFFER_BYTES: u32 = 64 * 1024;

#[wasm_bindgen(wasm_bindgen = worker::wasm_bindgen)]
extern "C" {
    /// A `ReadableStream` or a `WritableStream` of the socket.
    type RawStream;

    #[wasm_bindgen(method, catch, js_name = getReader)]
    fn get_reader(this: &RawStream) -> Result<RawReader, JsValue>;

    #[wasm_bindgen(method, catch, js_name = getReader)]
    fn get_reader_with(this: &RawStream, options: &Object) -> Result<RawReader, JsValue>;

    #[wasm_bindgen(method, catch, js_name = getWriter)]
    fn get_writer(this: &RawStream) -> Result<RawWriter, JsValue>;

    /// A default reader or a "bring your own buffer" reader.
    type RawReader;

    #[wasm_bindgen(method, catch, js_name = read)]
    fn read(this: &RawReader) -> Result<Promise, JsValue>;

    #[wasm_bindgen(method, catch, js_name = read)]
    fn read_into(this: &RawReader, view: &Uint8Array) -> Result<Promise, JsValue>;

    /// What a read resolves to: `{ done, value }`.
    type ReadResult;

    #[wasm_bindgen(method, getter)]
    fn done(this: &ReadResult) -> bool;

    #[wasm_bindgen(method, getter)]
    fn value(this: &ReadResult) -> JsValue;

    type RawWriter;

    #[wasm_bindgen(method, catch, js_name = write)]
    fn write(this: &RawWriter, chunk: &Uint8Array) -> Result<Promise, JsValue>;

    #[wasm_bindgen(method, catch, js_name = close)]
    fn close(this: &RawWriter) -> Result<Promise, JsValue>;
}

/// The runtime's error as an [`io::Error`], with the text `worker::Socket`
/// gives the same error.
fn js_error(value: JsValue) -> io::Error {
    let text = if let Some(text) = value.as_string() {
        text
    } else if let Some(error) = value.dyn_ref::<JsError>() {
        error.to_string().into()
    } else {
        format!("Error interpreting JsError: {value:?}")
    };
    io::Error::other(text)
}

/// The socket's readable side, behind one reader held for its life.
struct SocketChunks {
    reader: RawReader,
    /// Reads go into a buffer of ours (`reader` is a "bring your own
    /// buffer" reader).
    into_buffer: bool,
    /// The buffer for the next read, back from the chunk read before.
    spare: Option<ArrayBuffer>,
    in_flight: Option<JsFuture>,
}

impl SocketChunks {
    fn start_read(&mut self) -> io::Result<JsFuture> {
        let promise = if self.into_buffer {
            // A read hands its buffer to the runtime; the chunk that
            // comes back is a view of the same memory (`recycle`).
            let buffer = self
                .spare
                .take()
                .unwrap_or_else(|| ArrayBuffer::new(READ_BUFFER_BYTES));
            let view = Uint8Array::new_with_byte_offset_and_length(&buffer, 0, READ_BUFFER_BYTES);
            self.reader.read_into(&view)
        } else {
            self.reader.read()
        };
        promise.map(JsFuture::from).map_err(js_error)
    }
}

impl ChunkPort for SocketChunks {
    type Chunk = Uint8Array;

    fn poll_chunk(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Uint8Array>>> {
        let mut read = match self.in_flight.take() {
            Some(read) => read,
            None => match self.start_read() {
                Ok(read) => read,
                Err(e) => return Poll::Ready(Err(e)),
            },
        };
        let settled = match Pin::new(&mut read).poll(cx) {
            Poll::Pending => {
                self.in_flight = Some(read);
                return Poll::Pending;
            }
            Poll::Ready(settled) => settled,
        };
        let result: ReadResult = match settled {
            Ok(result) => result.unchecked_into(),
            Err(e) => return Poll::Ready(Err(js_error(e))),
        };
        if result.done() {
            return Poll::Ready(Ok(None));
        }
        Poll::Ready(match result.value().dyn_into::<Uint8Array>() {
            Ok(chunk) => Ok(Some(chunk)),
            Err(_) => Err(io::Error::other(
                "the socket's stream handed over something that is not bytes",
            )),
        })
    }

    fn chunk_len(chunk: &Uint8Array) -> usize {
        chunk.length() as usize
    }

    fn copy_out(chunk: &Uint8Array, at: usize, dst: &mut [u8]) {
        if at == 0 && dst.len() == chunk.length() as usize {
            chunk.copy_to(dst);
        } else {
            // Offsets fit: a chunk is no longer than `u32::MAX`.
            chunk
                .subarray(at as u32, (at + dst.len()) as u32)
                .copy_to(dst);
        }
    }

    fn recycle(&mut self, chunk: Uint8Array) {
        if self.into_buffer {
            let buffer = chunk.buffer();
            if buffer.byte_length() == READ_BUFFER_BYTES {
                self.spare = Some(buffer);
            }
        }
    }
}

/// A `connect()` socket as a byte stream (see the module text).
pub(super) struct WorkerStream {
    socket: worker_sys::Socket,
    reader: ChunkReader<SocketChunks>,
    writer: RawWriter,
    /// The write in flight and the length it reports when it settles.
    write: Option<(JsFuture, usize)>,
    close: Option<JsFuture>,
}

impl WorkerStream {
    /// Opens `hostname:port`; under the runtime's TLS when `tls`.
    pub(super) fn open(hostname: &str, port: u16, tls: bool) -> Result<Self, JsValue> {
        let address = Object::new();
        Reflect::set(&address, &"hostname".into(), &JsValue::from_str(hostname))?;
        Reflect::set(
            &address,
            &"port".into(),
            &JsValue::from_f64(f64::from(port)),
        )?;
        let options = Object::new();
        Reflect::set(&options, &"allowHalfOpen".into(), &JsValue::FALSE)?;
        let secure = if tls { "on" } else { "off" };
        Reflect::set(
            &options,
            &"secureTransport".into(),
            &JsValue::from_str(secure),
        )?;
        Self::new(worker_sys::connect(address.into(), options.into())?)
    }

    /// Takes the reader and the writer of `socket`. On an error the
    /// socket is asked to close.
    pub(super) fn new(socket: worker_sys::Socket) -> Result<Self, JsValue> {
        let taken = Self::take_streams(&socket);
        match taken {
            Ok((reader, into_buffer, writer)) => Ok(WorkerStream {
                socket,
                reader: ChunkReader::new(SocketChunks {
                    reader,
                    into_buffer,
                    spare: None,
                    in_flight: None,
                }),
                writer,
                write: None,
                close: None,
            }),
            Err(e) => {
                let _ = socket.close();
                Err(e)
            }
        }
    }

    fn take_streams(socket: &worker_sys::Socket) -> Result<(RawReader, bool, RawWriter), JsValue> {
        let readable: RawStream = socket.readable()?.unchecked_into();
        let writable: RawStream = socket.writable()?.unchecked_into();
        let mode = Object::new();
        Reflect::set(&mode, &"mode".into(), &JsValue::from_str("byob"))?;
        // A stream that does not take reads into a caller's buffer
        // refuses this reader and is left unlocked.
        let (reader, into_buffer) = match readable.get_reader_with(&mode) {
            Ok(reader) => (reader, true),
            Err(_) => (readable.get_reader()?, false),
        };
        Ok((reader, into_buffer, writable.get_writer()?))
    }

    /// Polls the write in flight to its end.
    fn poll_write_in_flight(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let Some((mut write, len)) = self.write.take() else {
            return Poll::Ready(Ok(0));
        };
        match Pin::new(&mut write).poll(cx) {
            Poll::Pending => {
                self.write = Some((write, len));
                Poll::Pending
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(len)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(js_error(e))),
        }
    }
}

/// See the module text; `close()` is called and its promise let go.
impl Drop for WorkerStream {
    fn drop(&mut self) {
        let _ = self.socket.close();
    }
}

impl AsyncRead for WorkerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let dst = buf.initialize_unfilled();
        match self.reader.poll_read(cx, dst) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for WorkerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write.is_none() {
            // The bytes are copied out before the call returns: the
            // caller's buffer is free while the write is in flight.
            let write = self
                .writer
                .write(&Uint8Array::from(buf))
                .map_err(js_error)?;
            self.write = Some((JsFuture::from(write), buf.len()));
        }
        self.poll_write_in_flight(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_write_in_flight(cx).map_ok(|_| ())
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The write in flight ends before the writable side is closed.
        match self.poll_write_in_flight(cx) {
            Poll::Ready(Ok(_)) => {}
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        }
        let mut close = match self.close.take() {
            Some(close) => close,
            None => JsFuture::from(self.writer.close().map_err(js_error)?),
        };
        match Pin::new(&mut close).poll(cx) {
            Poll::Pending => {
                self.close = Some(close);
                Poll::Pending
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(js_error(e))),
        }
    }
}
