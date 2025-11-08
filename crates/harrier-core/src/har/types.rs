use serde::{Deserialize, Serialize};

/// Top-level HAR object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Har {
    pub log: Log,
}

/// Main HAR log object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    pub version: String,
    pub creator: Creator,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser: Option<Creator>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pages: Option<Vec<Page>>,
    pub entries: Vec<Entry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Creator/Browser information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Creator {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Page information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page {
    #[serde(rename = "startedDateTime")]
    pub started_date_time: String,
    pub id: String,
    pub title: String,
    #[serde(rename = "pageTimings")]
    pub page_timings: PageTimings,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Page timing information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageTimings {
    #[serde(rename = "onContentLoad", skip_serializing_if = "Option::is_none")]
    pub on_content_load: Option<f64>,
    #[serde(rename = "onLoad", skip_serializing_if = "Option::is_none")]
    pub on_load: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Individual HTTP transaction entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    #[serde(rename = "pageref", skip_serializing_if = "Option::is_none")]
    pub page_ref: Option<String>,
    #[serde(rename = "startedDateTime")]
    pub started_date_time: String,
    pub time: f64,
    pub request: Request,
    pub response: Response,
    pub cache: Cache,
    pub timings: Timings,
    #[serde(rename = "serverIPAddress", skip_serializing_if = "Option::is_none")]
    pub server_ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// HTTP request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub method: String,
    pub url: String,
    #[serde(rename = "httpVersion")]
    pub http_version: String,
    pub cookies: Vec<Cookie>,
    pub headers: Vec<Header>,
    #[serde(rename = "queryString")]
    pub query_string: Vec<QueryParam>,
    #[serde(rename = "postData", skip_serializing_if = "Option::is_none")]
    pub post_data: Option<PostData>,
    #[serde(rename = "headersSize")]
    pub headers_size: i64,
    #[serde(rename = "bodySize")]
    pub body_size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// HTTP response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub status: i64,
    #[serde(rename = "statusText")]
    pub status_text: String,
    #[serde(rename = "httpVersion")]
    pub http_version: String,
    pub cookies: Vec<Cookie>,
    pub headers: Vec<Header>,
    pub content: Content,
    #[serde(rename = "redirectURL")]
    pub redirect_url: String,
    #[serde(rename = "headersSize")]
    pub headers_size: i64,
    #[serde(rename = "bodySize")]
    pub body_size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Cookie
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(rename = "httpOnly", skip_serializing_if = "Option::is_none")]
    pub http_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// HTTP header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Query parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryParam {
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// POST data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostData {
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Vec<Param>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// POST parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Param {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(rename = "fileName", skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(rename = "contentType", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Response content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Content {
    pub size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression: Option<i64>,
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Cache information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cache {
    #[serde(rename = "beforeRequest", skip_serializing_if = "Option::is_none")]
    pub before_request: Option<CacheEntry>,
    #[serde(rename = "afterRequest", skip_serializing_if = "Option::is_none")]
    pub after_request: Option<CacheEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Cache entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub expires: Option<String>,
    #[serde(rename = "lastAccess")]
    pub last_access: String,
    #[serde(rename = "eTag")]
    pub e_tag: String,
    #[serde(rename = "hitCount")]
    pub hit_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Timing information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect: Option<f64>,
    pub send: f64,
    pub wait: f64,
    pub receive: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}
