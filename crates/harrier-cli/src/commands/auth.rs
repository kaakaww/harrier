use crate::OutputFormat;
use anyhow::Result;
use harrier_core::har::HarReader;
use harrier_detectors::{AuthAnalysis, AuthAnalyzer, AuthSummaryGenerator, Severity};
use std::path::Path;

pub fn execute(
    file: &Path,
    _host_filter: Option<&str>,
    show_flows: bool,
    show_jwt: bool,
    security_only: bool,
    format: OutputFormat,
) -> Result<()> {
    let har = HarReader::from_file(file)?;
    let auth_analysis = AuthAnalyzer::analyze(&har)?;

    match format {
        OutputFormat::Json => output_json(&auth_analysis)?,
        OutputFormat::Table => output_table(&auth_analysis, security_only)?,
        OutputFormat::Pretty => {
            output_pretty(&auth_analysis, file, show_flows, show_jwt, security_only)?
        }
    }

    Ok(())
}

fn output_pretty(
    auth: &AuthAnalysis,
    file: &Path,
    _show_flows: bool,
    show_jwt: bool,
    security_only: bool,
) -> Result<()> {
    use console::style;

    let file_name = file
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    println!(
        "\n{}",
        style(format!("Authentication Analysis: {}", file_name))
            .bold()
            .cyan()
    );
    println!();

    // If security_only, skip to security findings
    if security_only {
        print_security_findings(auth);
        return Ok(());
    }

    // Generate summary
    if let Some(summary) = AuthSummaryGenerator::generate_summary(auth) {
        // Primary Method
        println!("{}", style("Primary Method").bold());
        println!(
            "  {} ({})",
            style(&summary.primary_method.method_type).green().bold(),
            match summary.primary_method.confidence {
                harrier_detectors::ConfidenceLevel::High => "High confidence",
                harrier_detectors::ConfidenceLevel::Medium => "Medium confidence",
                harrier_detectors::ConfidenceLevel::Low => "Low confidence",
            }
        );
        println!("  {}", summary.primary_method.description);

        // Session Mechanism
        println!("\n{}", style("Session").bold());
        println!("  {}", summary.session_mechanism.mechanism_type);
        println!("  {}", style(&summary.session_mechanism.details).dim());

        // Key Endpoints
        if !summary.key_endpoints.is_empty() {
            println!("\n{}", style("Key Endpoints").bold());
            for endpoint in summary.key_endpoints.iter().take(8) {
                println!(
                    "  {} {:<30} {}",
                    style(&endpoint.method).yellow(),
                    endpoint.path,
                    style(&endpoint.purpose).dim()
                );
            }
            if summary.key_endpoints.len() > 8 {
                println!(
                    "  ... and {} more",
                    summary.key_endpoints.len() - 8
                );
            }
        }
    } else {
        println!("{}", style("No authentication detected").yellow());
        println!("\n{}", style("Possible reasons:").bold());
        println!("  1. HAR was captured before authentication");
        println!("  2. Application uses unsupported authentication");
        println!("  3. Cookies/headers were sanitized from HAR");
        println!("\n{}", style("Recommendations:").bold());
        println!("  - Capture from login through authenticated requests");
        println!("  - Verify cookies and Authorization headers included");
        return Ok(());
    }

    // Flow Sequence (if flows detected or --flows requested)
    if !auth.flows.is_empty() {
        println!("\n{}", style("Flow Sequence").bold());
        for flow in &auth.flows {
            println!(
                "\n  {} ({:.0}ms)",
                style(flow.flow_type.as_str()).cyan().bold(),
                flow.duration_ms
            );
            for (i, step) in flow.steps.iter().enumerate() {
                println!(
                    "    {}. {} {}",
                    i + 1,
                    style(&step.method).yellow(),
                    truncate_url(&step.url, 50)
                );
                println!("       {}", style(&step.description).dim());
            }
        }
    }

    // JWT Details (if requested or tokens found)
    if show_jwt && !auth.jwt_tokens.is_empty() {
        println!("\n{}", style("JWT Tokens").bold());
        for (i, token) in auth.jwt_tokens.iter().enumerate() {
            println!("\n  Token #{}", i + 1);
            if let Some(ref alg) = token.header.alg {
                println!("    Algorithm:  {}", alg);
            }
            if let Some(ref iss) = token.claims.iss {
                println!("    Issuer:     {}", iss);
            }
            if let Some(ref sub) = token.claims.sub {
                println!("    Subject:    {}", sub);
            }
            if let Some(exp) = token.claims.exp {
                // Calculate lifetime if iat is present
                if let Some(iat) = token.claims.iat {
                    let lifetime = exp - iat;
                    println!("    Lifetime:   {} seconds", lifetime);
                }
            }
            println!("    Usage:      {} requests", token.usage_count);
        }

        // JWT Issues
        if !auth.jwt_issues.is_empty() {
            println!("\n  {}", style("JWT Issues:").red().bold());
            for issue in &auth.jwt_issues {
                let severity_icon = match issue.severity {
                    Severity::Critical => style("[CRITICAL]").red().bold(),
                    Severity::Warning => style("[WARN]").yellow(),
                    Severity::Info => style("[INFO]").dim(),
                };
                println!("    {} {}", severity_icon, issue.message);
            }
        }
    }

    // Security findings (always show summary)
    print_security_findings(auth);

    println!();
    Ok(())
}

fn print_security_findings(auth: &AuthAnalysis) {
    use console::style;

    let security_summary = AuthSummaryGenerator::aggregate_security_findings(auth);
    let total = security_summary.critical.len()
        + security_summary.warnings.len()
        + security_summary.info.len();

    if total == 0 {
        println!("\n{}", style("Security").bold());
        println!("  {} No issues detected", style("[OK]").green());
        return;
    }

    println!("\n{}", style("Security").bold());

    // Critical issues
    for finding in &security_summary.critical {
        println!(
            "  {} {} ({} occurrence{})",
            style("[CRITICAL]").red().bold(),
            finding.message,
            finding.count,
            if finding.count > 1 { "s" } else { "" }
        );
    }

    // Warnings
    for finding in security_summary.warnings.iter().take(5) {
        println!(
            "  {} {} ({} occurrence{})",
            style("[WARN]").yellow(),
            finding.message,
            finding.count,
            if finding.count > 1 { "s" } else { "" }
        );
    }
    if security_summary.warnings.len() > 5 {
        println!(
            "  {} ... and {} more warnings",
            style("[WARN]").yellow(),
            security_summary.warnings.len() - 5
        );
    }

    // Info (just count)
    if !security_summary.info.is_empty() {
        println!(
            "  {} {} informational findings",
            style("[INFO]").dim(),
            security_summary.info.len()
        );
    }

    // Token exposures
    if !auth.advanced_security.token_exposures.is_empty() {
        println!(
            "\n  {} Token exposures detected:",
            style("Warning:").yellow().bold()
        );
        for exposure in auth.advanced_security.token_exposures.iter().take(3) {
            println!("    - {}", exposure.message);
        }
        if auth.advanced_security.token_exposures.len() > 3 {
            println!(
                "    ... and {} more",
                auth.advanced_security.token_exposures.len() - 3
            );
        }
    }

    // CORS issues
    if !auth.advanced_security.cors_issues.is_empty() {
        println!(
            "\n  {} CORS issues detected:",
            style("Warning:").yellow().bold()
        );
        for issue in auth.advanced_security.cors_issues.iter().take(3) {
            println!("    - {}", issue.message);
        }
    }
}

fn truncate_url(url: &str, max_len: usize) -> String {
    if url.len() <= max_len {
        url.to_string()
    } else {
        format!("{}...", &url[..max_len - 3])
    }
}

fn output_json(auth: &AuthAnalysis) -> Result<()> {
    let json_str = serde_json::to_string_pretty(auth)?;
    println!("{}", json_str);
    Ok(())
}

fn output_table(auth: &AuthAnalysis, security_only: bool) -> Result<()> {
    if !security_only {
        // Methods
        println!("Auth Methods");
        for method in &auth.methods {
            println!("{}", method.as_str());
        }

        // Sessions
        if !auth.sessions.is_empty() {
            println!("\nSession,Type,Requests,Duration (s)");
            for session in &auth.sessions {
                let session_type = match &session.session_type {
                    harrier_detectors::SessionType::Cookie { name } => format!("Cookie:{}", name),
                    harrier_detectors::SessionType::BearerToken { is_jwt } => {
                        if *is_jwt {
                            "Bearer:JWT".to_string()
                        } else {
                            "Bearer:Token".to_string()
                        }
                    }
                    harrier_detectors::SessionType::ApiKey { header_name } => {
                        format!("ApiKey:{}", header_name)
                    }
                };
                println!(
                    "\"{}\",{},{},{:.1}",
                    session.identifier,
                    session_type,
                    session.request_count,
                    session.duration_ms / 1000.0
                );
            }
        }

        // Flows
        if !auth.flows.is_empty() {
            println!("\nFlow Type,Steps,Duration (ms)");
            for flow in &auth.flows {
                println!(
                    "\"{}\",{},{:.0}",
                    flow.flow_type.as_str(),
                    flow.steps.len(),
                    flow.duration_ms
                );
            }
        }
    }

    // Security findings
    let security_summary = AuthSummaryGenerator::aggregate_security_findings(auth);

    println!("\nSeverity,Finding,Count");
    for finding in &security_summary.critical {
        println!("Critical,\"{}\",{}", finding.message, finding.count);
    }
    for finding in &security_summary.warnings {
        println!("Warning,\"{}\",{}", finding.message, finding.count);
    }
    for finding in &security_summary.info {
        println!("Info,\"{}\",{}", finding.message, finding.count);
    }

    Ok(())
}
