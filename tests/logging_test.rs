//! Tests for the logging module

use nexuscore_mcp::utils::logging::{get_metrics, PerfMetrics};

#[test]
fn test_perf_metrics_new() {
    let metrics = PerfMetrics::new();
    let stats = metrics.get_stats();

    assert_eq!(stats["total_calls"], 0);
    assert_eq!(stats["cache_hits"], 0);
    assert_eq!(stats["cache_misses"], 0);
    assert_eq!(stats["total_duration_ms"], 0);
}

#[test]
fn test_perf_metrics_record_call() {
    let metrics = PerfMetrics::new();

    metrics.record_call(100, false); // cache miss
    metrics.record_call(50, true); // cache hit
    metrics.record_call(75, false); // cache miss

    let stats = metrics.get_stats();

    assert_eq!(stats["total_calls"], 3);
    assert_eq!(stats["cache_hits"], 1);
    assert_eq!(stats["cache_misses"], 2);
    assert_eq!(stats["total_duration_ms"], 225);
}

#[test]
fn test_cache_hit_rate_calculation() {
    let metrics = PerfMetrics::new();

    // 2 hits, 2 misses = 50% hit rate
    metrics.record_call(10, true);
    metrics.record_call(10, true);
    metrics.record_call(10, false);
    metrics.record_call(10, false);

    let stats = metrics.get_stats();
    let hit_rate = stats["cache_hit_rate"].as_f64().unwrap();

    assert!((hit_rate - 50.0).abs() < 0.01);
}

#[test]
fn test_cache_hit_rate_zero_calls() {
    let metrics = PerfMetrics::new();
    let stats = metrics.get_stats();

    // Should be 0 when no calls recorded
    assert_eq!(stats["cache_hit_rate"], 0.0);
}

#[test]
fn test_global_metrics() {
    let metrics = get_metrics();

    // Should always return the same instance
    let metrics2 = get_metrics();

    metrics.record_call(10, false);

    // Both references should see the same data
    let stats = metrics2.get_stats();
    assert!(stats["total_calls"].as_u64().unwrap() > 0);
}

#[test]
fn test_metrics_thread_safety() {
    use std::sync::Arc;
    use std::thread;

    let metrics = Arc::new(PerfMetrics::new());
    let mut handles = vec![];

    for _ in 0..10 {
        let m = Arc::clone(&metrics);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                m.record_call(1, false);
            }
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let stats = metrics.get_stats();
    assert_eq!(stats["total_calls"], 1000);
}
