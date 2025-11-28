use crate::OutputFormat;
use anyhow::Result;
use harrier_core::har::{Entry, Har, HarReader};
use harrier_detectors::AuthMethod;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use url::Url;

/// Configuration for a single host
#[derive(Debug, Clone, serde::Serialize)]
pub struct HostConfig {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub is_primary: bool,
    pub is_scannable: bool,
    pub yaml_config: String,
    pub notes: Vec<String>,
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

/// Detect auth method for entries
fn detect_auth_method(entries: &[&Entry]) -> Option<AuthMethod> {
    for entry in entries {
        for header in &entry.request.headers {
            if header.name.to_lowercase() == "authorization" {
                let value = header.value.to_lowercase();
                if value.starts_with("bearer") {
                    let token = header.value.trim_start_matches("Bearer ").trim();
                    if token.matches('.').count() == 2 {
                        return Some(AuthMethod::Jwt);
                    }
                    return Some(AuthMethod::Bearer);
                } else if value.starts_with("basic") {
                    return Some(AuthMethod::Basic);
                }
            }
            let header_lower = header.name.to_lowercase();
            if header_lower == "x-api-key" || header_lower == "api-key" || header_lower == "apikey"
            {
                return Some(AuthMethod::ApiKey(header.name.clone()));
            }
        }

        for cookie in &entry.request.cookies {
            let name_lower = cookie.name.to_lowercase();
            if name_lower.contains("session")
                || name_lower.contains("auth")
                || name_lower.contains("token")
            {
                return Some(AuthMethod::Cookie);
            }
        }
    }
    None
}

/// Determine if a host is typically scannable
fn is_scannable_host(host: &str, _role: Option<&str>) -> bool {
    let host_lower = host.to_lowercase();

    // OAuth/IdP providers are usually not scanned
    if host_lower.contains("auth0")
        || host_lower.contains("okta")
        || host_lower.contains("cognito")
        || host_lower.contains("login.microsoftonline")
    {
        return false;
    }

    // Analytics/tracking are not scanned
    if host_lower.contains("analytics")
        || host_lower.contains("segment")
        || host_lower.contains("mixpanel")
        || host_lower.contains("google-analytics")
    {
        return false;
    }

    // CDNs are usually not scanned
    if host_lower.contains("cloudfront")
        || host_lower.contains("akamai")
        || host_lower.contains("fastly")
    {
        return false;
    }

    // Monitoring tools
    if host_lower.contains("sentry")
        || host_lower.contains("datadog")
        || host_lower.contains("newrelic")
    {
        return false;
    }

    true
}

/// Infer role of a host
fn infer_role(host: &str) -> Option<&'static str> {
    let host_lower = host.to_lowercase();

    if host_lower.contains("auth0")
        || host_lower.contains("okta")
        || host_lower.contains("cognito")
    {
        return Some("OAuth Provider");
    }
    if host_lower.contains("cdn") || host_lower.contains("static") {
        return Some("CDN");
    }
    if host_lower.contains("analytics") || host_lower.contains("segment") {
        return Some("Analytics");
    }

    None
}

/// Generate YAML configuration for a host
fn generate_yaml_config(
    host: &str,
    port: u16,
    protocol: &str,
    har_file: &Path,
    auth_method: Option<&AuthMethod>,
    is_primary: bool,
) -> (String, Vec<String>) {
    let mut yaml = String::new();
    let mut notes = Vec::new();

    let host_url = if (protocol == "https" && port == 443) || (protocol == "http" && port == 80) {
        format!("{}://{}", protocol, host)
    } else {
        format!("{}://{}:{}", protocol, host, port)
    };

    let har_path = har_file
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "recording.har".to_string());

    // Basic config
    yaml.push_str("app:\n");
    yaml.push_str("  applicationId: ${APP_ID}\n");
    yaml.push_str(&format!("  host: {}\n", host_url));
    yaml.push_str("  env: ${APP_ENV}\n");
    yaml.push('\n');

    // HAR spider config
    yaml.push_str("hawk:\n");
    yaml.push_str("  spider:\n");
    yaml.push_str("    har:\n");
    yaml.push_str("      file:\n");
    yaml.push_str("        paths:\n");
    yaml.push_str(&format!("          - {}\n", har_path));

    // Authentication config based on detected method
    if let Some(auth) = auth_method {
        yaml.push('\n');
        match auth {
            AuthMethod::Jwt | AuthMethod::Bearer => {
                yaml.push_str("authentication:\n");
                yaml.push_str("  type: oauth2\n");
                yaml.push_str("  oauth2:\n");
                yaml.push_str("    tokenUrl: ${OAUTH_TOKEN_URL}\n");
                yaml.push_str("    clientId: ${OAUTH_CLIENT_ID}\n");
                yaml.push_str("    clientSecret: ${OAUTH_CLIENT_SECRET}\n");
                notes.push("OAuth 2.0 / JWT detected - configure token endpoint".to_string());
                if matches!(auth, AuthMethod::Jwt) {
                    notes.push("JWT tokens detected - ensure token lifetime covers scan duration".to_string());
                }
            }
            AuthMethod::Basic => {
                yaml.push_str("authentication:\n");
                yaml.push_str("  type: basic\n");
                yaml.push_str("  basic:\n");
                yaml.push_str("    username: ${BASIC_USERNAME}\n");
                yaml.push_str("    password: ${BASIC_PASSWORD}\n");
                notes.push("Basic Auth detected".to_string());
            }
            AuthMethod::ApiKey(header_name) => {
                yaml.push_str("authentication:\n");
                yaml.push_str("  type: header\n");
                yaml.push_str("  header:\n");
                yaml.push_str(&format!("    name: {}\n", header_name));
                yaml.push_str("    value: ${API_KEY}\n");
                notes.push(format!("API Key in {} header detected", header_name));
            }
            AuthMethod::Cookie => {
                yaml.push_str("authentication:\n");
                yaml.push_str("  type: cookie\n");
                yaml.push_str("  cookie:\n");
                yaml.push_str("    name: ${SESSION_COOKIE_NAME}\n");
                yaml.push_str("    value: ${SESSION_COOKIE_VALUE}\n");
                notes.push("Cookie-based session detected".to_string());
                notes.push("Consider using form-based login for automatic session handling".to_string());
            }
            AuthMethod::OAuth => {
                yaml.push_str("authentication:\n");
                yaml.push_str("  type: oauth2\n");
                yaml.push_str("  oauth2:\n");
                yaml.push_str("    tokenUrl: ${OAUTH_TOKEN_URL}\n");
                yaml.push_str("    clientId: ${OAUTH_CLIENT_ID}\n");
                yaml.push_str("    clientSecret: ${OAUTH_CLIENT_SECRET}\n");
                notes.push("OAuth flow detected - configure token endpoint".to_string());
            }
            AuthMethod::Custom(header_name) => {
                yaml.push_str("authentication:\n");
                yaml.push_str("  type: header\n");
                yaml.push_str("  header:\n");
                yaml.push_str(&format!("    name: {}\n", header_name));
                yaml.push_str("    value: ${AUTH_TOKEN}\n");
                notes.push(format!("Custom auth header {} detected", header_name));
            }
        }
    } else if is_primary {
        notes.push("No authentication detected - may need manual configuration".to_string());
    }

    (yaml, notes)
}

/// Build configurations for all hosts
fn build_host_configs(har: &Har, har_file: &Path, host_filter: Option<&str>, all_hosts: bool) -> Vec<HostConfig> {
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

    let primary_root_domain = first_host_key.as_ref().and_then(|key| {
        host_entries
            .get(key)
            .map(|(_, domain, _, _)| get_root_domain(domain))
    });

    let mut configs: Vec<HostConfig> = Vec::new();

    for (key, (protocol, domain, port, entries)) in &host_entries {
        // Apply host filter if specified
        if let Some(filter) = host_filter {
            if !domain.contains(filter) {
                continue;
            }
        }

        let is_primary = first_host_key.as_ref() == Some(key);
        let root_domain = get_root_domain(domain);
        let _is_same_domain = primary_root_domain
            .as_ref()
            .is_some_and(|first| &root_domain == first);

        // Skip non-scannable hosts unless --all-hosts or it's the primary
        let role = infer_role(domain);
        let is_scannable = is_scannable_host(domain, role);

        if !all_hosts && !is_primary && !is_scannable {
            continue;
        }

        // Detect auth method for this host
        let auth_method = detect_auth_method(entries);

        let (yaml_config, mut notes) =
            generate_yaml_config(domain, *port, protocol, har_file, auth_method.as_ref(), is_primary);

        // Add role-based notes
        if let Some(r) = role {
            if !is_scannable {
                notes.insert(0, format!("{} - typically not scanned", r));
            }
        }

        configs.push(HostConfig {
            host: domain.clone(),
            port: *port,
            protocol: protocol.clone(),
            is_primary,
            is_scannable,
            yaml_config,
            notes,
        });
    }

    // Sort: primary first, then scannable by request count
    configs.sort_by(|a, b| {
        match (a.is_primary, b.is_primary) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => {
                match (a.is_scannable, b.is_scannable) {
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    _ => std::cmp::Ordering::Equal,
                }
            }
        }
    });

    configs
}

pub fn execute(
    file: &Path,
    host_filter: Option<&str>,
    all_hosts: bool,
    output_file: Option<std::path::PathBuf>,
    format: OutputFormat,
) -> Result<()> {
    let har = HarReader::from_file(file)?;
    let configs = build_host_configs(&har, file, host_filter, all_hosts);

    let output = match format {
        OutputFormat::Json => format_json(&configs)?,
        OutputFormat::Table => format_table(&configs)?,
        OutputFormat::Pretty => format_pretty(&configs, file)?,
    };

    if let Some(out_path) = output_file {
        let mut f = fs::File::create(&out_path)?;
        f.write_all(output.as_bytes())?;
        println!("Configuration written to: {}", out_path.display());
    } else {
        print!("{}", output);
    }

    Ok(())
}

fn format_pretty(configs: &[HostConfig], file: &Path) -> Result<String> {
    use console::style;

    let mut output = String::new();

    let file_name = file
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    output.push_str(&format!(
        "\n{}\n\n",
        style(format!("HawkScan Configuration: {}", file_name))
            .bold()
            .cyan()
    ));

    for config in configs {
        let host_display = if config.is_primary {
            format!(
                "# {} (Primary Target)\n# {}\n",
                config.host,
                "=".repeat(config.host.len() + 18)
            )
        } else if !config.is_scannable {
            format!(
                "# {} ({})\n# {}\n",
                config.host,
                "Not typically scanned",
                "=".repeat(config.host.len() + 24)
            )
        } else {
            format!(
                "# {}\n# {}\n",
                config.host,
                "=".repeat(config.host.len())
            )
        };

        output.push_str(&host_display);

        if config.is_scannable || config.is_primary {
            output.push('\n');
            output.push_str(&config.yaml_config);

            if !config.notes.is_empty() {
                output.push_str("\n# Notes:\n");
                for note in &config.notes {
                    output.push_str(&format!("# - {}\n", note));
                }
            }
        } else {
            output.push_str(&format!("# {} is typically not included in security scans.\n", config.host));
            if let Some(note) = config.notes.first() {
                output.push_str(&format!("# {}\n", note));
            }
        }

        output.push_str("\n---\n\n");
    }

    // Usage instructions
    output.push_str("# Usage:\n");
    output.push_str("#   1. Copy the configuration for your target host to stackhawk.yml\n");
    output.push_str("#   2. Set required environment variables (APP_ID, APP_ENV, auth vars)\n");
    output.push_str("#   3. Run: hawk scan\n");
    output.push_str("#\n");
    output.push_str("# Documentation: https://docs.stackhawk.com/hawkscan/\n");

    Ok(output)
}

fn format_json(configs: &[HostConfig]) -> Result<String> {
    Ok(serde_json::to_string_pretty(configs)?)
}

fn format_table(configs: &[HostConfig]) -> Result<String> {
    let mut output = String::new();
    output.push_str("Host,Port,Primary,Scannable,Notes\n");
    for config in configs {
        let notes = config.notes.join("; ");
        output.push_str(&format!(
            "{},{},{},{},\"{}\"\n",
            config.host,
            config.port,
            config.is_primary,
            config.is_scannable,
            notes
        ));
    }
    Ok(output)
}
