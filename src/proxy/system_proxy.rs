use std::process::Command;
use thiserror::Error;
use tracing::{info, warn};

#[derive(Debug, Error)]
pub enum SystemProxyError {
    #[error("failed to detect network service: {0}")]
    Detection(String),
    #[error("failed to set system proxy: {0}")]
    Set(String),
    #[error("unsupported platform")]
    Unsupported,
}

/// Saved proxy state for restoration on shutdown.
pub struct ProxyGuard {
    network_service: String,
    prev_web_proxy: ProxyState,
    prev_secure_proxy: ProxyState,
}

struct ProxyState {
    enabled: bool,
    host: String,
    port: String,
}

impl ProxyGuard {
    /// Detect the active network service, save current proxy settings,
    /// and set the system proxy to the given host:port.
    pub fn enable(host: &str, port: u16) -> Result<Self, SystemProxyError> {
        if !cfg!(target_os = "macos") && !cfg!(target_os = "linux") {
            return Err(SystemProxyError::Unsupported);
        }

        if cfg!(target_os = "macos") {
            Self::enable_macos(host, port)
        } else {
            Self::enable_linux(host, port)
        }
    }

    /// Restore original proxy settings.
    pub fn disable(&self) -> Result<(), SystemProxyError> {
        if cfg!(target_os = "macos") {
            self.disable_macos()
        } else {
            self.disable_linux()
        }
    }

    // -- macOS via networksetup --

    fn enable_macos(host: &str, port: u16) -> Result<Self, SystemProxyError> {
        let service = detect_macos_service()?;

        let prev_web_proxy = get_macos_proxy_state(&service, "getwebproxy")?;
        let prev_secure_proxy = get_macos_proxy_state(&service, "getsecurewebproxy")?;

        let port_str = port.to_string();

        run_cmd("networksetup", &["-setwebproxy", &service, host, &port_str])?;
        run_cmd("networksetup", &["-setsecurewebproxy", &service, host, &port_str])?;

        info!(
            service = %service,
            host = %host,
            port = %port,
            "system proxy enabled"
        );

        Ok(Self {
            network_service: service,
            prev_web_proxy,
            prev_secure_proxy,
        })
    }

    fn disable_macos(&self) -> Result<(), SystemProxyError> {
        let svc = &self.network_service;

        if self.prev_web_proxy.enabled {
            run_cmd("networksetup", &[
                "-setwebproxy", svc,
                &self.prev_web_proxy.host,
                &self.prev_web_proxy.port,
            ])?;
        } else {
            run_cmd("networksetup", &["-setwebproxystate", svc, "off"])?;
        }

        if self.prev_secure_proxy.enabled {
            run_cmd("networksetup", &[
                "-setsecurewebproxy", svc,
                &self.prev_secure_proxy.host,
                &self.prev_secure_proxy.port,
            ])?;
        } else {
            run_cmd("networksetup", &["-setsecurewebproxystate", svc, "off"])?;
        }

        info!(service = %svc, "system proxy restored");
        Ok(())
    }

    // -- Linux via gsettings --

    fn enable_linux(host: &str, port: u16) -> Result<Self, SystemProxyError> {
        let prev_web_proxy = get_linux_proxy_state("http")?;
        let prev_secure_proxy = get_linux_proxy_state("https")?;

        let port_str = port.to_string();

        run_cmd("gsettings", &["set", "org.gnome.system.proxy", "mode", "manual"])?;
        run_cmd("gsettings", &["set", "org.gnome.system.proxy.http", "host", host])?;
        run_cmd("gsettings", &["set", "org.gnome.system.proxy.http", "port", &port_str])?;
        run_cmd("gsettings", &["set", "org.gnome.system.proxy.https", "host", host])?;
        run_cmd("gsettings", &["set", "org.gnome.system.proxy.https", "port", &port_str])?;

        info!(host = %host, port = %port, "system proxy enabled (GNOME)");

        Ok(Self {
            network_service: "gnome".to_string(),
            prev_web_proxy,
            prev_secure_proxy,
        })
    }

    fn disable_linux(&self) -> Result<(), SystemProxyError> {
        if self.prev_web_proxy.enabled {
            run_cmd("gsettings", &["set", "org.gnome.system.proxy.http", "host", &self.prev_web_proxy.host])?;
            run_cmd("gsettings", &["set", "org.gnome.system.proxy.http", "port", &self.prev_web_proxy.port])?;
            run_cmd("gsettings", &["set", "org.gnome.system.proxy.https", "host", &self.prev_secure_proxy.host])?;
            run_cmd("gsettings", &["set", "org.gnome.system.proxy.https", "port", &self.prev_secure_proxy.port])?;
        } else {
            run_cmd("gsettings", &["set", "org.gnome.system.proxy", "mode", "none"])?;
        }

        info!("system proxy restored (GNOME)");
        Ok(())
    }
}

impl Drop for ProxyGuard {
    fn drop(&mut self) {
        if let Err(e) = self.disable() {
            warn!(error = %e, "failed to restore system proxy settings on drop");
        }
    }
}

// -- helpers --

fn detect_macos_service() -> Result<String, SystemProxyError> {
    // Get the primary network service (the one routing default traffic)
    let output = Command::new("networksetup")
        .args(["-listallnetworkservices"])
        .output()
        .map_err(|e| SystemProxyError::Detection(e.to_string()))?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Try common service names in priority order
    for candidate in ["Wi-Fi", "Ethernet", "USB 10/100/1000 LAN", "Thunderbolt Ethernet"] {
        if stdout.lines().any(|line| line.trim() == candidate) {
            return Ok(candidate.to_string());
        }
    }

    // Fall back to first non-asterisk line
    for line in stdout.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('*') && !trimmed.contains("denotes") {
            return Ok(trimmed.to_string());
        }
    }

    Err(SystemProxyError::Detection(
        "no active network service found".into(),
    ))
}

fn get_macos_proxy_state(service: &str, getter: &str) -> Result<ProxyState, SystemProxyError> {
    let output = Command::new("networksetup")
        .args([&format!("-{getter}"), service])
        .output()
        .map_err(|e| SystemProxyError::Detection(e.to_string()))?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut enabled = false;
    let mut host = String::new();
    let mut port = String::new();

    for line in stdout.lines() {
        if let Some(val) = line.strip_prefix("Enabled: ") {
            enabled = val.trim() == "Yes";
        } else if let Some(val) = line.strip_prefix("Server: ") {
            host = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("Port: ") {
            port = val.trim().to_string();
        }
    }

    Ok(ProxyState {
        enabled,
        host,
        port,
    })
}

fn get_linux_proxy_state(scheme: &str) -> Result<ProxyState, SystemProxyError> {
    let mode = Command::new("gsettings")
        .args(["get", "org.gnome.system.proxy", "mode"])
        .output()
        .map_err(|e| SystemProxyError::Detection(e.to_string()))?;

    let mode_str = String::from_utf8_lossy(&mode.stdout).trim().replace('\'', "");
    let enabled = mode_str == "manual";

    let host_output = Command::new("gsettings")
        .args(["get", &format!("org.gnome.system.proxy.{scheme}"), "host"])
        .output()
        .map_err(|e| SystemProxyError::Detection(e.to_string()))?;

    let port_output = Command::new("gsettings")
        .args(["get", &format!("org.gnome.system.proxy.{scheme}"), "port"])
        .output()
        .map_err(|e| SystemProxyError::Detection(e.to_string()))?;

    Ok(ProxyState {
        enabled,
        host: String::from_utf8_lossy(&host_output.stdout).trim().replace('\'', ""),
        port: String::from_utf8_lossy(&port_output.stdout).trim().to_string(),
    })
}

fn run_cmd(cmd: &str, args: &[&str]) -> Result<(), SystemProxyError> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| SystemProxyError::Set(format!("{cmd}: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SystemProxyError::Set(format!(
            "{cmd} {}: {}",
            args.join(" "),
            stderr.trim()
        )));
    }

    Ok(())
}
