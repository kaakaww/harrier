mod performance;
mod summary;

pub use performance::PerformanceAnalyzer;
pub use summary::SummaryAnalyzer;

use crate::har::Har;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub summary: SummaryStats,
    pub performance: PerformanceStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummaryStats {
    pub total_entries: usize,
    pub total_size: u64,
    pub unique_domains: usize,
    pub date_range: Option<(String, String)>,
    pub http_versions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceStats {
    pub total_time: f64,
    pub average_time: f64,
    pub median_time: f64,
    pub slowest_requests: Vec<SlowRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlowRequest {
    pub url: String,
    pub time: f64,
    pub method: String,
    pub status: i64,
}

pub trait Analyzer {
    type Output;

    fn analyze(&self, har: &Har) -> crate::Result<Self::Output>;
}
