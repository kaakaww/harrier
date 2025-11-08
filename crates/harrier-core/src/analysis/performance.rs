use super::{Analyzer, PerformanceStats, SlowRequest};
use crate::Result;
use crate::har::Har;

pub struct PerformanceAnalyzer {
    top_n: usize,
}

impl PerformanceAnalyzer {
    pub fn new(top_n: usize) -> Self {
        Self { top_n }
    }
}

impl Default for PerformanceAnalyzer {
    fn default() -> Self {
        Self::new(10)
    }
}

impl Analyzer for PerformanceAnalyzer {
    type Output = PerformanceStats;

    fn analyze(&self, har: &Har) -> Result<Self::Output> {
        tracing::debug!("Analyzing HAR performance statistics");

        let entries = &har.log.entries;

        if entries.is_empty() {
            return Ok(PerformanceStats {
                total_time: 0.0,
                average_time: 0.0,
                median_time: 0.0,
                slowest_requests: vec![],
            });
        }

        // Calculate total time
        let total_time: f64 = entries.iter().map(|e| e.time).sum();
        let average_time = total_time / entries.len() as f64;

        // Calculate median time
        let mut times: Vec<f64> = entries.iter().map(|e| e.time).collect();
        times.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median_time = if times.len().is_multiple_of(2) {
            let mid = times.len() / 2;
            (times[mid - 1] + times[mid]) / 2.0
        } else {
            times[times.len() / 2]
        };

        // Find slowest requests
        let mut slow_requests: Vec<_> = entries
            .iter()
            .map(|e| SlowRequest {
                url: e.request.url.clone(),
                time: e.time,
                method: e.request.method.clone(),
                status: e.response.status,
            })
            .collect();

        slow_requests.sort_by(|a, b| b.time.partial_cmp(&a.time).unwrap());
        slow_requests.truncate(self.top_n);

        tracing::info!(
            "Performance analysis complete: avg={:.2}ms, median={:.2}ms",
            average_time,
            median_time
        );

        Ok(PerformanceStats {
            total_time,
            average_time,
            median_time,
            slowest_requests: slow_requests,
        })
    }
}
