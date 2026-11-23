use velmora_bridge::audit::{audit, AuditCounts};
use velmora_bridge::copy::{pass_due, START_WINDOW_MS};
use velmora_bridge::ports::Clock;
use velmora_bridge::recovery::{start_after, Layout};
use velmora_bridge::remote::S3Remote;
use velmora_bridge::UnixMs;
use worker::{console_error, js_sys::Math, Env};

use crate::{d1::D1Sql, e2::FetchHttp, env::WorkerClock, r2::R2Blobs, recovery_log};

pub fn pass_at(scheduled: UnixMs) -> Option<UnixMs> {
    let pass = UnixMs(scheduled.0 - START_WINDOW_MS);
    (pass.0 > 0 && pass_due(pass)).then_some(pass)
}

fn random_start(now: UnixMs, slot: usize, fraction: f64) -> String {
    let layout = &Layout::all()[slot / 4];
    let tail = (fraction * 4_294_967_296.0) as u32;
    // Time-key families need positions *inside* their timestamp space.
    // Choose the age at a logarithmic scale so the years before the
    // first record don't dwarf the recent years, months, and weeks.
    const HOUR: i64 = 3_600_000;
    let cutoff = (now.0 - 48 * HOUR).max(0);
    let hours = (cutoff / HOUR + 1) as f64;
    let age = ((hours.powf(fraction) - 1.0) * HOUR as f64) as i64;
    let at = UnixMs((cutoff - age).max(0));
    match slot % 4 {
        0 => format!("{}art/x_{tail:08x}", layout.root()),
        1 => start_after(&layout.generation_prefix(), at),
        2 => start_after(&layout.tombstone_prefix(), at),
        _ => start_after(&format!("{}seg/s_", layout.root()), at),
    }
}

pub async fn run(env: Env, pass: UnixMs, remote: S3Remote<FetchHttp>) {
    let Ok(db) = env.d1("CATALOG").map(D1Sql::new) else {
        console_error!("recovery copy: audit telemetry database unavailable");
        return;
    };
    let now = WorkerClock.now();
    let sample = async {
        let counts = match env.bucket("SAFETY") {
            Ok(bucket) => {
                audit(
                    &R2Blobs::new(bucket),
                    &remote,
                    &WorkerClock,
                    now,
                    &random_start(now, (Math::random() * 8.0) as usize, Math::random()),
                    |remaining| (Math::random() * remaining as f64) as usize,
                )
                .await
            }
            Err(_) => AuditCounts {
                source_errors: 1,
                ..Default::default()
            },
        };
        let log = recovery_log::Log {
            at: WorkerClock.now(),
            pass,
            destination: Some(remote.place()),
            first: remote.transport().first_problem.get(),
        };
        if log.audit(&db, &counts).await.is_err() {
            console_error!("recovery copy: audit telemetry write failed");
        }
    };
    futures_util::join!(sample, prune_log(&db, now));
}

async fn prune_log(db: &D1Sql, now: UnixMs) {
    if recovery_log::prune(db, now).await.is_err() {
        console_error!("recovery copy: telemetry prune failed");
    }
}

pub async fn prune_after_refused_pass(env: Env) {
    match env.d1("CATALOG").map(D1Sql::new) {
        Ok(db) => prune_log(&db, WorkerClock.now()).await,
        Err(_) => console_error!("recovery copy: telemetry prune failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::{pass_at, random_start};
    use velmora_bridge::copy::{PASS_INTERVAL_MS, START_WINDOW_MS};
    use velmora_bridge::UnixMs;

    #[test]
    fn random_probe_moves_inside_all_supported_key_families() {
        let now = UnixMs(1_800_000_000_000);
        for (slot, prefix) in ["art/x_", "g_", "del/g_", "seg/s_"].into_iter().enumerate() {
            for (offset, root) in [(0, "m/"), (4, "m/x/t_0000000000000000/")] {
                let a = random_start(now, slot + offset, 0.1);
                let b = random_start(now, slot + offset, 0.5);
                assert!(a.starts_with(&format!("{root}{prefix}")));
                assert!(b.starts_with(&format!("{root}{prefix}")));
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn audit_only_runs_on_the_cron_tick_after_the_pass_starts() {
        let pass = PASS_INTERVAL_MS * 100;
        assert_eq!(pass_at(UnixMs(pass)), None);
        assert_eq!(pass_at(UnixMs(pass + START_WINDOW_MS)), Some(UnixMs(pass)));
        assert_eq!(pass_at(UnixMs(pass + 2 * START_WINDOW_MS)), None);
    }
}
