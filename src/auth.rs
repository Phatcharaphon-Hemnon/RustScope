use axum::http::HeaderMap;
use ring::pbkdf2;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::num::NonZeroU32;
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
    let key = token();
    save_account(dir, user, &digest(&key))?;
    println!("{key}");
    Ok(())
}

const PASSWORD_ROUNDS: NonZeroU32 = match NonZeroU32::new(600_000) {
    Some(rounds) => rounds,
    None => panic!("password iteration count must be nonzero"),
};

pub fn valid_registration(user: &str, password: &str) -> bool {
    label(user) && !user.starts_with('.') && password.len() <= 256 && password.chars().count() >= 12
}

pub fn register(dir: &Path, user: &str, password: &str) -> std::io::Result<()> {
    if !valid_registration(user, password) {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    let salt = Uuid::new_v4();
    let mut hash = [0; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        PASSWORD_ROUNDS,
        salt.as_bytes(),
        password.as_bytes(),
        &mut hash,
    );
    save_account(
        dir,
        user,
        &format!("{}:{}", salt.simple(), hex::encode(hash)),
    )
}

fn save_account(dir: &Path, user: &str, hash: &str) -> std::io::Result<()> {
    let accounts = dir.join("accounts");
    state_dir(&accounts)?;
    let pending = accounts.join(format!(".{}", token()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&pending)?;
    // Publish the completed credential without overwriting an existing account.
    let result = file
        .write_all(hash.as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::hard_link(&pending, accounts.join(user)));
    let _ = fs::remove_file(pending);
    result
}

fn verified_password(saved: &str, password: &str) -> bool {
    let Some((salt, hash)) = saved.split_once(':') else {
        // CLI accounts use generated, high-entropy tokens.
        let password = password.trim();
        return password.len() == 32 && saved == digest(password);
    };
    let (Ok(salt), Ok(hash)) = (Uuid::parse_str(salt), hex::decode(hash)) else {
        return false;
    };
    hash.len() == 32
        && pbkdf2::verify(
            pbkdf2::PBKDF2_HMAC_SHA256,
            PASSWORD_ROUNDS,
            salt.as_bytes(),
            password.as_bytes(),
            &hash,
        )
        .is_ok()
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
        if !label(user) || user.starts_with('.') || password.len() > 256 {
            return None;
        }
        let saved = fs::read_to_string(dir.join("accounts").join(user)).ok()?;
        if !verified_password(&saved, password) {
            return None;
        }
        self.start(user)
    }

    pub fn start(&self, user: &str) -> Option<String> {
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
