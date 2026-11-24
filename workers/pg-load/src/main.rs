#[cfg(not(target_arch = "wasm32"))]
mod local {
    use futures_channel::oneshot;
    use std::env;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use tokio_postgres::{Config, NoTls};
    use velmora_bridge::pg::{classify_connect_error, PgConnect, PgConnection};
    use velmora_bridge::Result;
    use velmora_pg_load::{parse_config, run, Runtime};

    #[derive(Clone)]
    struct Local(Config);
    impl PgConnect for Local {
        async fn connect(&self) -> Result<PgConnection> {
            let (client, connection) = self
                .0
                .connect(NoTls)
                .await
                .map_err(classify_connect_error)?;
            let (closed, done) = oneshot::channel();
            let driver = tokio::spawn(async move {
                let _ = connection.await;
                let _ = closed.send(());
            });
            Ok(
                PgConnection::new(client, move || driver.abort()).with_shutdown(async move {
                    let _ = done.await;
                }),
            )
        }
    }

    struct Clock(Instant);
    impl Runtime for Clock {
        fn monotonic_ms(&self) -> f64 {
            self.0.elapsed().as_secs_f64() * 1000.0
        }
        fn wall_ms(&self) -> i64 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock")
                .as_millis() as i64
        }
        async fn sleep(&self, duration: Duration) {
            tokio::time::sleep(duration).await;
        }
    }

    pub fn main() -> std::result::Result<(), String> {
        let schema = env::var("PG_LOAD_SCHEMA")
            .map_err(|_| "set PG_LOAD_SCHEMA to a local scratch schema")?;
        if !schema.starts_with("velmora_pg_load_")
            || schema.len() > 63
            || !schema
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(
                "PG_LOAD_SCHEMA must be a velmora_pg_load_ scratch schema identifier".into(),
            );
        }
        let cfg = parse_config(&env::var("PG_LOAD_CONFIG").map_err(|_| "set PG_LOAD_CONFIG")?)?;
        let mut writer = Config::new();
        writer
            .host_path("/var/run/postgresql")
            .dbname("postgres")
            .user(&env::var("USER").map_err(|_| "USER required for local peer auth")?)
            .connect_timeout(Duration::from_secs(5))
            .options(format!("-c search_path={schema},pg_catalog,pg_temp"))
            .application_name("velmora-pg-load-write");
        let mut reader = writer.clone();
        reader.application_name("velmora-pg-load-read");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| "could not start runtime")?;
        let report = rt.block_on(run(
            Local(writer),
            Local(reader),
            &Clock(Instant::now()),
            &cfg,
        ))?;
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|_| "report serialization failed")?
        );
        if report.meets_local_rate() {
            Ok(())
        } else {
            Err("local rate or measurement acceptance failed".into())
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn main() -> std::process::ExitCode {
    match local::main() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("pg-load: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn main() {}
