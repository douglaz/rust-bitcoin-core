use anyhow::{Result, bail};
use base64::{Engine as _, engine::general_purpose};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

/// Authentication middleware for RPC server
#[derive(Clone)]
pub struct AuthMiddleware {
    enabled: bool,
    username: Option<String>,
    password: Option<String>,
    cookie_path: Option<PathBuf>,
    whitelisted_ips: HashSet<String>,
}

impl AuthMiddleware {
    /// Create new auth middleware
    pub fn new(enabled: bool) -> Result<Self> {
        let mut auth = Self {
            enabled,
            username: None,
            password: None,
            cookie_path: None,
            whitelisted_ips: HashSet::new(),
        };

        if enabled {
            auth.load_credentials()?;
        }

        // Always whitelist localhost
        auth.whitelisted_ips.insert("127.0.0.1".to_string());
        auth.whitelisted_ips.insert("::1".to_string());

        Ok(auth)
    }

    /// Load authentication credentials
    fn load_credentials(&mut self) -> Result<()> {
        // Try to load from environment variables first
        if let (Ok(user), Ok(pass)) = (
            std::env::var("RPC_USER"),
            std::env::var("RPC_PASSWORD")
        ) {
            self.username = Some(user);
            self.password = Some(pass);
            debug!("Loaded RPC credentials from environment");
            return Ok(());
        }

        // Try to load from cookie file (Bitcoin Core style)
        let cookie_path = self.find_cookie_file()?;
        if let Ok(cookie) = fs::read_to_string(&cookie_path) {
            let parts: Vec<&str> = cookie.trim().split(':').collect();
            if parts.len() == 2 {
                self.username = Some(parts[0].to_string());
                self.password = Some(parts[1].to_string());
                self.cookie_path = Some(cookie_path);
                debug!("Loaded RPC credentials from cookie file");
                return Ok(());
            }
        }

        // Generate new cookie file if none exists
        self.generate_cookie_auth()?;
        
        Ok(())
    }

    /// Find the cookie file location
    fn find_cookie_file(&self) -> Result<PathBuf> {
        // Check standard locations
        let possible_paths = vec![
            PathBuf::from(".cookie"),
            PathBuf::from("~/.bitcoin/.cookie"),
            PathBuf::from("/tmp/.cookie"),
        ];

        for path in possible_paths {
            let expanded = if path.starts_with("~") {
                if let Some(home) = dirs::home_dir() {
                    home.join(path.strip_prefix("~/").unwrap())
                } else {
                    path
                }
            } else {
                path
            };

            if expanded.exists() {
                return Ok(expanded);
            }
        }

        // Default to current directory
        Ok(PathBuf::from(".cookie"))
    }

    /// Generate new cookie authentication
    fn generate_cookie_auth(&mut self) -> Result<()> {
        let username = "__cookie__";
        let password: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let cookie_content = format!("{}:{}", username, password);
        let cookie_path = PathBuf::from(".cookie");
        
        fs::write(&cookie_path, &cookie_content)?;
        
        self.username = Some(username.to_string());
        self.password = Some(password);
        self.cookie_path = Some(cookie_path);
        
        debug!("Generated new cookie authentication");
        Ok(())
    }

    /// Validate authentication header
    pub fn validate_auth_header(&self, auth_header: Option<&str>) -> Result<bool> {
        if !self.enabled {
            return Ok(true);
        }

        let auth_header = auth_header.ok_or_else(|| {
            anyhow::anyhow!("Authorization header required")
        })?;

        if !auth_header.starts_with("Basic ") {
            bail!("Invalid authorization type, expected Basic");
        }

        let encoded = &auth_header[6..];
        let decoded = general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| anyhow::anyhow!("Invalid base64 encoding: {}", e))?;
        
        let credentials = String::from_utf8(decoded)
            .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in credentials: {}", e))?;
        
        let parts: Vec<&str> = credentials.split(':').collect();
        if parts.len() != 2 {
            bail!("Invalid credentials format");
        }

        let (user, pass) = (parts[0], parts[1]);
        
        // Validate against stored credentials
        if let (Some(expected_user), Some(expected_pass)) = (&self.username, &self.password) {
            if user == expected_user && pass == expected_pass {
                return Ok(true);
            }
        }

        bail!("Invalid credentials")
    }

    /// Check if IP is whitelisted
    pub fn is_ip_whitelisted(&self, ip: &str) -> bool {
        self.whitelisted_ips.contains(ip)
    }

    /// Add IP to whitelist
    pub fn whitelist_ip(&mut self, ip: String) {
        self.whitelisted_ips.insert(ip);
    }
}

/// Authentication configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    pub enabled: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub cookie_file: Option<String>,
    pub whitelisted_ips: Vec<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            username: None,
            password: None,
            cookie_file: Some(".cookie".to_string()),
            whitelisted_ips: vec!["127.0.0.1".to_string(), "::1".to_string()],
        }
    }
}