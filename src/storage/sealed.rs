use anyhow::{Context, Result, anyhow, ensure};
use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    io::{ErrorKind, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub(super) fn key_path(path: &Path) -> PathBuf {
    let mut sidecar = OsString::from(path.as_os_str());
    sidecar.push(".key");
    PathBuf::from(sidecar)
}

pub(super) fn key(db: &Path) -> Result<LessSafeKey> {
    let path = key_path(db);
    let mut bytes = [0u8; 32];
    match File::open(&path) {
        Ok(mut file) => {
            let metadata = file.metadata()?;
            ensure!(
                metadata.is_file()
                    && metadata.len() == 32
                    && metadata.permissions().mode() & 0o077 == 0,
                "invalid storage encryption key file: {}",
                path.display()
            );
            file.read_exact(&mut bytes)?;
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            ensure!(
                !db.try_exists()?,
                "storage encryption key is missing: {}",
                path.display()
            );
            SystemRandom::new()
                .fill(&mut bytes)
                .map_err(|_| anyhow!("storage encryption key generation failed"))?;
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&path)
                .with_context(|| format!("creating storage encryption key: {}", path.display()))?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                File::open(parent)?.sync_all()?;
            }
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("opening storage encryption key: {}", path.display()));
        }
    }
    Ok(LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, &bytes)
            .map_err(|_| anyhow!("invalid storage encryption key"))?,
    ))
}

pub(super) fn seal(key: &LessSafeKey, field: &str, id: &str, value: &str) -> Result<String> {
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| anyhow!("storage encryption nonce generation failed"))?;
    let mut encrypted = value.as_bytes().to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(format!("{field}:{id}")),
        &mut encrypted,
    )
    .map_err(|_| anyhow!("storage encryption failed"))?;
    Ok(format!("{}{}", hex::encode(nonce), hex::encode(encrypted)))
}

pub(super) fn open(key: &LessSafeKey, field: &str, id: &str, value: &str) -> Result<String> {
    let mut sealed = hex::decode(value).map_err(|_| anyhow!("invalid encrypted storage field"))?;
    let (nonce, encrypted) = sealed
        .split_at_mut_checked(NONCE_LEN)
        .ok_or_else(|| anyhow!("invalid encrypted storage field"))?;
    let nonce = Nonce::try_assume_unique_for_key(nonce)
        .map_err(|_| anyhow!("invalid encrypted storage nonce"))?;
    let plaintext = key
        .open_in_place(nonce, Aad::from(format!("{field}:{id}")), encrypted)
        .map_err(|_| anyhow!("storage decryption failed; check the encryption key"))?;
    Ok(std::str::from_utf8(plaintext)?.to_owned())
}
