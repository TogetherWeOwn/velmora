use crate::{parse_config, run, Runtime};
use futures_channel::oneshot;
use futures_util::future::abortable;
use std::time::Duration;
use tokio_postgres::Config;
use velmora_bridge::pg::{classify_connect_error, PgConnect, PgConnection};
use velmora_bridge::{BridgeError, Result as BridgeResult};
use worker::{
    event, postgres_tls::PassthroughTls, wasm_bindgen_futures::spawn_local, Context, Delay, Env,
    Hyperdrive, Method, Request, Response, Result, SecureTransport, Socket,
};

// Store the binding name, not a socket, connection string, or client. Each
// adapter call owns its Hyperdrive connection in this request's I/O context.
#[derive(Clone)]
struct Connector(Env, &'static str);
impl PgConnect for Connector {
    async fn connect(&self) -> BridgeResult<PgConnection> {
        let binding: Hyperdrive = self.0.hyperdrive(self.1).map_err(|_| connect_failed())?;
        let config: Config = binding
            .connection_string()
            .parse()
            .map_err(|_| connect_failed())?;
        let socket = Socket::builder()
            .secure_transport(SecureTransport::StartTls)
            .connect(binding.host(), binding.port())
            .map_err(|_| connect_failed())?;
        let (client, connection) = config
            .connect_raw(socket, PassthroughTls)
            .await
            .map_err(classify_connect_error)?;
        let (closed, done) = oneshot::channel();
        let (driver, stop) = abortable(connection);
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

fn connect_failed() -> BridgeError {
    BridgeError::Sql("pg: statement failed".into())
}

struct Clock;
impl Runtime for Clock {
    // Workers' clock advances at I/O boundaries. These timings include the
    // per-call Hyperdrive round trips and have millisecond resolution.
    fn monotonic_ms(&self) -> f64 {
        worker::js_sys::Date::now()
    }
    fn wall_ms(&self) -> i64 {
        worker::js_sys::Date::now() as i64
    }
    async fn sleep(&self, duration: Duration) {
        Delay::from(duration).await;
    }
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _: Context) -> Result<Response> {
    if req.method() != Method::Post
        || req.path() != "/run"
        || env
            .var("PG_LOAD_ENABLE")
            .ok()
            .is_none_or(|v| v.to_string() != "drill-only")
    {
        return Response::error("not found", 404);
    }
    let Ok(raw) = env.var("PG_LOAD_CONFIG") else {
        return Response::error("missing drill configuration", 400);
    };
    let cfg = match parse_config(&raw.to_string()) {
        Ok(cfg) => cfg,
        Err(error) => return Response::error(error, 400),
    };
    match run(
        Connector(env.clone(), "DRILL_PG_WRITE"),
        Connector(env, "DRILL_PG_READ"),
        &Clock,
        &cfg,
    )
    .await
    {
        Ok(report) => Response::from_json(&report),
        Err(error) => Response::error(error, 500),
    }
}
