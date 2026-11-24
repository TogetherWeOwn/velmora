use velmora_pg_load::{parse_config, percentile, Family};

#[test]
fn schedules_committed_batch_units_not_operation_counts() {
    let plan = parse_config(
        r#"{"batches_per_minute":300,"minutes":5,"mix":{"put_publish":3,"outbox_post_claim":2}}"#,
    )
    .unwrap()
    .plan();
    assert_eq!(
        plan.iter().map(|job| job.family.batches()).sum::<u32>(),
        1500
    );
    assert_eq!(
        plan.iter()
            .filter(|job| job.family == Family::PutPublish)
            .count(),
        450
    );
    assert_eq!(plan.first().unwrap().at_ms, 0);
    assert!(plan.last().unwrap().at_ms < 300_000);
}

#[test]
fn schedules_a_twenty_minute_high_rate_drill() {
    let cfg = parse_config(
        r#"{"batches_per_minute":11000,"minutes":20,"mix":{"put_publish":4,"delete":3,"outbox_post_claim":1}}"#,
    )
    .unwrap();
    let plan = cfg.plan();
    assert_eq!(
        plan.iter().map(|job| job.family.batches()).sum::<u32>(),
        220_000
    );
    assert!(plan.last().unwrap().at_ms < 1_200_000);
}

#[test]
fn invalid_and_unbounded_runs_are_refused() {
    for config in [
        r#"{"batches_per_minute":0,"minutes":5,"mix":{"put_publish":1}}"#,
        r#"{"batches_per_minute":300,"minutes":21,"mix":{"put_publish":1}}"#,
        r#"{"batches_per_minute":300,"minutes":5,"mix":{"unexpected":1}}"#,
        r#"{"batches_per_minute":300,"minutes":5,"mix":{"gc":0}}"#,
    ] {
        assert!(parse_config(config).is_err(), "accepted {config}");
    }
}

#[test]
fn refuses_impossible_read_coverage_before_a_run_starts() {
    let config = |rate| {
        format!(
            r#"{{"batches_per_minute":300,"minutes":5,"reads_per_minute":{rate},"unloaded_seconds":30,"mix":{{"gc":1}}}}"#
        )
    };
    assert!(parse_config(&config(1200)).is_ok());
    assert_eq!(
        parse_config(&config(1199)).unwrap_err(),
        "load configuration cannot schedule minimum reads per type in both phases"
    );
}

#[test]
fn rejects_a_write_plan_below_the_rate_tolerance() {
    let config =
        |rate| format!(r#"{{"batches_per_minute":{rate},"minutes":1,"mix":{{"delete":1}}}}"#);
    assert!(parse_config(&config(4)).is_err()); // Plans 3, but needs 4.
    assert!(parse_config(&config(6)).is_ok());
    assert!(parse_config(&config(20)).is_err()); // Plans 18, but needs 19.
    assert!(parse_config(&config(22)).is_ok()); // Plans 21, which is within 5%.
}

#[test]
fn nearest_rank_percentile_does_not_impute_missing_observations() {
    assert_eq!(percentile(&mut [], 99), None);
    assert_eq!(percentile(&mut [10., 5., 8., 1.], 95), Some(10.));
    assert_eq!(percentile(&mut [10., 5., 8., 1.], 50), Some(5.));
}
