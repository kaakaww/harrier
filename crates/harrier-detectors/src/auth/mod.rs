pub mod advanced_security;
pub mod analyzer;
pub mod events;
pub mod flows;
pub mod jwt;
pub mod methods;
pub mod saml;
pub mod security;
pub mod sessions;
pub mod summary;

// Re-export main types for convenience
pub use advanced_security::{
    AdvancedSecurityAnalysis, AdvancedSecurityAnalyzer, CorsIssue, CorsIssueType, CspFinding,
    CspFindingType, ExposureType, RefreshPatternType, TokenExposure, TokenRefreshPattern,
};
pub use analyzer::{AuthAnalysis, AuthAnalyzer};
pub use events::{AuthEvent, AuthEventType, EventDetails, EventDetector};
pub use flows::{AuthFlow, AuthFlowType, FlowDetector, FlowRole, FlowStep};
pub use jwt::{JwtAnalyzer, JwtClaims, JwtHeader, JwtIssueType, JwtSecurityIssue, JwtToken};
pub use methods::{AuthDetector, AuthMethod};
pub use saml::{SamlDetector, SamlFlow, SamlFlowType, SamlSecurityIssue, SamlStep, SamlStepRole};
pub use security::{SecurityAnalyzer, SecurityNote, Severity};
pub use sessions::{AuthSession, SessionAttributes, SessionTracker, SessionType};
pub use summary::{
    AggregatedFinding, AuthMethodSummary, AuthSummaryGenerator, AuthenticationSummary,
    ConfidenceLevel, EndpointInfo, HawkScanConfig, SecurityFindingsSummary,
    SessionMechanismSummary,
};
