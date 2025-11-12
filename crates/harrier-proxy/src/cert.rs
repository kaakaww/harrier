use crate::{Error, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType};
use std::fs;
use std::path::{Path, PathBuf};

/// Manages CA certificate generation and storage for MITM proxy
pub struct CertificateAuthority {
    cert_pem: String,
    key_pem: String,
}

impl CertificateAuthority {
    /// Generate a new CA certificate for MITM proxy use
    pub fn generate() -> Result<Self> {
        tracing::info!("Generating new CA certificate for Harrier proxy");

        // Create certificate parameters for a CA
        let mut params = CertificateParams::default();

        // Set up distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Harrier MITM Proxy CA");
        dn.push(DnType::OrganizationName, "Harrier");
        dn.push(DnType::CountryName, "US");
        params.distinguished_name = dn;

        // Mark as CA certificate
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        // Set key usages for CA
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];

        // Generate key pair
        let key_pair = rcgen::KeyPair::generate()
            .map_err(|e| Error::Tls(format!("Failed to generate key pair: {}", e)))?;

        // Generate self-signed certificate
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| Error::Tls(format!("Failed to generate CA certificate: {}", e)))?;

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        tracing::debug!("CA certificate generated successfully");

        Ok(Self { cert_pem, key_pem })
    }

    /// Load CA certificate from PEM files
    pub fn load_from_pem(cert_path: &Path, key_path: &Path) -> Result<Self> {
        tracing::debug!("Loading CA certificate from {:?}", cert_path);

        let cert_pem = fs::read_to_string(cert_path).map_err(Error::Io)?;

        let key_pem = fs::read_to_string(key_path).map_err(Error::Io)?;

        Ok(Self { cert_pem, key_pem })
    }

    /// Save CA certificate to PEM files
    pub fn save_to_pem(&self, cert_path: &Path, key_path: &Path) -> Result<()> {
        tracing::info!("Saving CA certificate to {:?}", cert_path);

        // Ensure parent directory exists
        if let Some(parent) = cert_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(cert_path, &self.cert_pem)?;
        fs::write(key_path, &self.key_pem)?;

        tracing::debug!("CA certificate saved successfully");

        Ok(())
    }

    /// Get the certificate PEM string
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Get the private key PEM string
    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }

    /// Get default CA certificate paths in ~/.harrier/
    pub fn default_paths() -> Result<(PathBuf, PathBuf)> {
        let home = dirs::home_dir()
            .ok_or_else(|| Error::Proxy("Could not determine home directory".to_string()))?;

        let harrier_dir = home.join(".harrier");
        let cert_path = harrier_dir.join("ca.crt");
        let key_path = harrier_dir.join("ca.key");

        Ok((cert_path, key_path))
    }

    /// Load or generate CA certificate from default location
    pub fn load_or_generate() -> Result<Self> {
        let (cert_path, key_path) = Self::default_paths()?;

        // Try to load existing certificate
        if cert_path.exists() && key_path.exists() {
            tracing::info!("Loading existing CA certificate");
            Self::load_from_pem(&cert_path, &key_path)
        } else {
            // Generate new certificate and save it
            tracing::info!("No existing CA certificate found, generating new one");
            let ca = Self::generate()?;
            ca.save_to_pem(&cert_path, &key_path)?;

            println!("✨ New CA certificate generated and saved to:");
            println!("   Certificate: {}", cert_path.display());
            println!("   Private Key: {}", key_path.display());
            println!();
            println!("⚠️  You must install this certificate in your system's trust store");
            println!("   to intercept HTTPS traffic. See documentation for instructions.");
            println!();

            Ok(ca)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ca() {
        let ca = CertificateAuthority::generate().unwrap();
        assert!(!ca.cert_pem().is_empty());
        assert!(!ca.key_pem().is_empty());
        assert!(ca.cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(ca.key_pem().contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_save_and_load() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cert_path = temp_dir.path().join("test-ca.crt");
        let key_path = temp_dir.path().join("test-ca.key");

        // Generate and save
        let ca1 = CertificateAuthority::generate().unwrap();
        ca1.save_to_pem(&cert_path, &key_path).unwrap();

        // Load and verify
        let ca2 = CertificateAuthority::load_from_pem(&cert_path, &key_path).unwrap();
        assert_eq!(ca1.cert_pem(), ca2.cert_pem());
        assert_eq!(ca1.key_pem(), ca2.key_pem());
    }
}
