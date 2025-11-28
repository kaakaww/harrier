use crate::OutputFormat;
use anyhow::Result;
use harrier_core::har::{Entry, Har, HarReader};
use harrier_detectors::AppTypeDetector;
use std::collections::HashMap;
use std::path::Path;
use url::Url;

/// Host information with full details for the map view
#[derive(Debug, Clone, serde::Serialize)]
pub struct HostMapInfo {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub request_count: usize,
    pub api_type: String,
    pub auth_method: Option<String>,
    pub role: Option<String>,
    pub is_primary: bool,
    pub category: HostCategory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum HostCategory {
    Primary,
    SameDomain,
    ThirdParty,
}

impl HostCategory {
    fn as_str(&self) -> &'static str {
        match self {
            HostCategory::Primary => "Primary Target",
            HostCategory::SameDomain => "Same Domain",
            HostCategory::ThirdParty => "Third Party",
        }
    }
}

/// Architecture map output
#[derive(Debug, Clone, serde::Serialize)]
pub struct ArchitectureMap {
    pub file_name: String,
    pub hosts: Vec<HostMapInfo>,
    pub relationships: Vec<HostRelationship>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HostRelationship {
    pub from: String,
    pub to: String,
    pub relationship_type: String,
}

/// Extract root domain using Public Suffix List
fn get_root_domain(domain: &str) -> String {
    if domain.parse::<std::net::IpAddr>().is_ok() {
        return domain.to_string();
    }

    match psl::domain(domain.as_bytes()) {
        Some(root) => String::from_utf8_lossy(root.as_bytes()).to_string(),
        None => {
            let parts: Vec<&str> = domain.split('.').collect();
            if parts.len() >= 2 {
                format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
            } else {
                domain.to_string()
            }
        }
    }
}

/// Detect auth method for a set of entries
fn detect_auth_for_entries(entries: &[&Entry]) -> Option<String> {
    for entry in entries {
        // Check Authorization header
        for header in &entry.request.headers {
            if header.name.to_lowercase() == "authorization" {
                let value = header.value.to_lowercase();
                if value.starts_with("bearer") {
                    // Check if it looks like a JWT
                    let token = header.value.trim_start_matches("Bearer ").trim();
                    if token.matches('.').count() == 2 {
                        return Some("Bearer JWT".to_string());
                    }
                    return Some("Bearer Token".to_string());
                } else if value.starts_with("basic") {
                    return Some("Basic Auth".to_string());
                }
            }
            // Check for API key headers
            let header_lower = header.name.to_lowercase();
            if header_lower == "x-api-key" || header_lower == "api-key" || header_lower == "apikey"
            {
                return Some(format!("API Key ({})", header.name));
            }
        }

        // Check for auth cookies
        for cookie in &entry.request.cookies {
            let name_lower = cookie.name.to_lowercase();
            if name_lower.contains("session")
                || name_lower.contains("auth")
                || name_lower.contains("token")
            {
                return Some("Cookie".to_string());
            }
        }
    }
    None
}

/// Infer the role of a host based on its characteristics
fn infer_host_role(host: &str, api_type: &str, _auth_method: &Option<String>) -> Option<String> {
    let host_lower = host.to_lowercase();

    // OAuth/Auth providers
    if host_lower.contains("auth0")
        || host_lower.contains("okta")
        || host_lower.contains("cognito")
        || host_lower.contains("oauth")
        || host_lower.contains("login")
        || host_lower.contains("identity")
    {
        return Some("Authentication provider".to_string());
    }

    // CDN/Static assets
    if host_lower.contains("cdn")
        || host_lower.contains("static")
        || host_lower.contains("assets")
        || host_lower.contains("cloudfront")
        || host_lower.contains("akamai")
    {
        return Some("CDN / Static assets".to_string());
    }

    // Analytics
    if host_lower.contains("analytics")
        || host_lower.contains("tracking")
        || host_lower.contains("segment")
        || host_lower.contains("mixpanel")
        || host_lower.contains("amplitude")
        || host_lower.contains("google-analytics")
    {
        return Some("Analytics".to_string());
    }

    // Monitoring
    if host_lower.contains("sentry")
        || host_lower.contains("datadog")
        || host_lower.contains("newrelic")
        || host_lower.contains("bugsnag")
    {
        return Some("Error monitoring".to_string());
    }

    // API type based inference
    if api_type == "GraphQL" {
        return Some("GraphQL API".to_string());
    }

    None
}

/// Analyze hosts and build the architecture map
fn build_architecture_map(
    har: &Har,
    target_override: Option<&str>,
    _show_all: bool,
) -> ArchitectureMap {
    let mut host_entries: HashMap<String, (String, String, u16, Vec<&Entry>)> = HashMap::new();
    let mut first_host_key: Option<String> = None;

    for entry in &har.log.entries {
        if let Ok(url) = Url::parse(&entry.request.url) {
            let protocol = url.scheme().to_string();
            let domain = url.host_str().unwrap_or("unknown").to_string();
            let port = url
                .port()
                .unwrap_or_else(|| if protocol == "https" { 443 } else { 80 });

            let key = format!("{}://{}:{}", protocol, domain, port);

            if first_host_key.is_none() {
                first_host_key = Some(key.clone());
            }

            host_entries
                .entry(key)
                .and_modify(|(_, _, _, entries)| entries.push(entry))
                .or_insert((protocol, domain, port, vec![entry]));
        }
    }

    // Determine primary host (use override if provided)
    let primary_key = if let Some(target) = target_override {
        host_entries
            .keys()
            .find(|k| k.contains(target))
            .cloned()
            .or(first_host_key.clone())
    } else {
        first_host_key.clone()
    };

    let primary_root_domain = primary_key.as_ref().and_then(|key| {
        host_entries
            .get(key)
            .map(|(_, domain, _, _)| get_root_domain(domain))
    });

    let mut hosts: Vec<HostMapInfo> = Vec::new();
    let mut relationships: Vec<HostRelationship> = Vec::new();

    for (key, (protocol, domain, port, entries)) in &host_entries {
        let is_primary = primary_key.as_ref() == Some(key);
        let root_domain = get_root_domain(domain);
        let is_same_domain = primary_root_domain
            .as_ref()
            .is_some_and(|first| &root_domain == first);

        let category = if is_primary {
            HostCategory::Primary
        } else if is_same_domain {
            HostCategory::SameDomain
        } else {
            HostCategory::ThirdParty
        };

        // Detect API type
        let api_type_results = AppTypeDetector::detect_for_host(entries);
        let api_type = api_type_results
            .first()
            .map(|(t, _, _)| t.as_str().to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        // Detect auth method
        let auth_method = detect_auth_for_entries(entries);

        // Infer role
        let role = infer_host_role(domain, &api_type, &auth_method);

        // Check for OAuth provider relationship
        if let Some(ref r) = role
            && r.contains("Authentication")
            && let Some(ref pk) = primary_key
            && let Some((_, primary_domain, _, _)) = host_entries.get(pk)
        {
            relationships.push(HostRelationship {
                from: primary_domain.clone(),
                to: domain.clone(),
                relationship_type: "oauth_provider".to_string(),
            });
        }

        hosts.push(HostMapInfo {
            host: domain.clone(),
            port: *port,
            protocol: protocol.clone(),
            request_count: entries.len(),
            api_type,
            auth_method,
            role,
            is_primary,
            category,
        });
    }

    // Sort hosts: primary first, then same domain by count, then third party by count
    hosts.sort_by(|a, b| match (a.category, b.category) {
        (HostCategory::Primary, _) => std::cmp::Ordering::Less,
        (_, HostCategory::Primary) => std::cmp::Ordering::Greater,
        (HostCategory::SameDomain, HostCategory::ThirdParty) => std::cmp::Ordering::Less,
        (HostCategory::ThirdParty, HostCategory::SameDomain) => std::cmp::Ordering::Greater,
        _ => b.request_count.cmp(&a.request_count),
    });

    let file_name = har.log.creator.name.clone();

    ArchitectureMap {
        file_name,
        hosts,
        relationships,
    }
}

pub fn execute(
    file: &Path,
    target: Option<&str>,
    show_all: bool,
    format: OutputFormat,
) -> Result<()> {
    let har = HarReader::from_file(file)?;
    let map = build_architecture_map(&har, target, show_all);

    match format {
        OutputFormat::Json => output_json(&map)?,
        OutputFormat::Table => output_table(&map)?,
        OutputFormat::Pretty => output_pretty(&map, file, show_all)?,
    }

    Ok(())
}

fn output_pretty(map: &ArchitectureMap, file: &Path, show_all: bool) -> Result<()> {
    use console::style;

    let file_name = file
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    println!(
        "\n{}",
        style(format!("Architecture Map: {}", file_name))
            .bold()
            .cyan()
    );
    println!();

    // Group hosts by category
    let primary: Vec<_> = map
        .hosts
        .iter()
        .filter(|h| h.category == HostCategory::Primary)
        .collect();
    let same_domain: Vec<_> = map
        .hosts
        .iter()
        .filter(|h| h.category == HostCategory::SameDomain)
        .collect();
    let third_party: Vec<_> = map
        .hosts
        .iter()
        .filter(|h| h.category == HostCategory::ThirdParty)
        .collect();

    // Primary Target section
    if !primary.is_empty() {
        println!("{}", style("Primary Target").bold().green());
        for host in &primary {
            print_host_tree(host, true);
        }
    }

    // Same Domain section
    if !same_domain.is_empty() {
        println!("\n{}", style("Same Domain").bold().yellow());
        for host in &same_domain {
            print_host_tree(host, false);
        }
    }

    // Third Party section
    let max_third_party = if show_all { third_party.len() } else { 5 };
    if !third_party.is_empty() {
        println!("\n{}", style("Third Party").bold().blue());
        for host in third_party.iter().take(max_third_party) {
            print_host_tree(host, false);
        }
        if !show_all && third_party.len() > 5 {
            println!(
                "  {} (use --all to see all)",
                style(format!("... and {} more", third_party.len() - 5)).dim()
            );
        }
    }

    // Host Summary table
    println!("\n{}", style("Host Summary").bold());
    println!(
        "  {:<35} {:>8}  {:<15} {}",
        style("Host").underlined(),
        style("Requests").underlined(),
        style("Type").underlined(),
        style("Auth").underlined()
    );

    for host in &map.hosts {
        let auth_display = host.auth_method.as_deref().unwrap_or("None");
        println!(
            "  {:<35} {:>8}  {:<15} {}",
            format!("{}:{}", host.host, host.port),
            host.request_count,
            host.api_type,
            auth_display
        );
    }

    println!();
    Ok(())
}

fn print_host_tree(host: &HostMapInfo, is_primary: bool) {
    use console::style;

    let host_display = format!("{}:{}", host.host, host.port);
    if is_primary {
        println!("  {}", style(&host_display).green().bold());
    } else {
        println!("  {}", host_display);
    }

    println!(
        "    Type:     {} ({} requests)",
        host.api_type, host.request_count
    );

    if let Some(ref auth) = host.auth_method {
        println!("    Auth:     {}", auth);
    } else {
        println!("    Auth:     {}", style("None").dim());
    }

    if let Some(ref role) = host.role {
        println!("    Role:     {}", style(role).cyan());
    }
}

fn output_json(map: &ArchitectureMap) -> Result<()> {
    let json_str = serde_json::to_string_pretty(map)?;
    println!("{}", json_str);
    Ok(())
}

fn output_table(map: &ArchitectureMap) -> Result<()> {
    println!("Category,Host,Port,Requests,API Type,Auth,Role");
    for host in &map.hosts {
        let auth = host.auth_method.as_deref().unwrap_or("");
        let role = host.role.as_deref().unwrap_or("");
        println!(
            "{},{},{},{},{},{},\"{}\"",
            host.category.as_str(),
            host.host,
            host.port,
            host.request_count,
            host.api_type,
            auth,
            role
        );
    }
    Ok(())
}
