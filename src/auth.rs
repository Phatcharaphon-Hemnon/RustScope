use axum::http::HeaderMap;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub fn token() -> String {
    Uuid::new_v4().simple().to_string()
}

pub fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .chars()
            .all(|c| c.is_alphanumeric() || "-_.".contains(c))
}

fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

pub fn state_dir(path: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

pub fn add_account(dir: &Path, user: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        label(user) && !user.starts_with('.'),
        "invalid account name"
    );
    state_dir(&dir.join("accounts"))?;
    let key = token();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.join("accounts").join(user))?;
    file.write_all(digest(&key).as_bytes())?;
    // Printed only by the local provisioning command, never by the web service.
    println!("{key}");
    Ok(())
}

#[derive(Clone)]
pub struct Session {
    pub user: String,
    pub csrf: String,
    expires: i64,
}

#[derive(Default)]
pub struct Sessions(Mutex<HashMap<String, Session>>);

impl Sessions {
    pub fn login(&self, dir: &Path, user: &str, password: &str) -> Option<String> {
        if !label(user) || user.starts_with('.') || password.len() != 32 {
            return None;
        }
        let saved = fs::read_to_string(dir.join("accounts").join(user)).ok()?;
        if saved != digest(password) {
            return None;
        }
        let key = token();
        let mut sessions = self.0.lock().ok()?;
        sessions.retain(|_, s| s.expires > now());
        sessions.insert(
            digest(&key),
            Session {
                user: user.into(),
                csrf: token(),
                expires: now() + 3600,
            },
        );
        Some(key)
    }

    pub fn get(&self, headers: &HeaderMap) -> Option<Session> {
        let cookie = headers
            .get("cookie")?
            .to_str()
            .ok()?
            .split(';')
            .find_map(|v| v.trim().strip_prefix("rustscope="))?;
        self.0
            .lock()
            .ok()?
            .get(&digest(cookie))
            .filter(|s| s.expires > now())
            .cloned()
    }
}
