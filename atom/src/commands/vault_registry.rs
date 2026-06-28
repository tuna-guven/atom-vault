use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultEntry {
    pub name: String,
    pub path: String,
    pub last_opened: u64,
}

fn get_registry_path() -> PathBuf {
    let mut p = dirs::home_dir().expect("home dir");
    p.push(".atom_vault");
    fs::create_dir_all(&p).ok();
    p.push("vaults.json");
    p
}

pub fn load_vault_registry() -> Vec<VaultEntry> {
    let path = get_registry_path();
    if let Ok(mut file) = fs::File::open(path) {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            if let Ok(entries) = serde_json::from_str::<Vec<VaultEntry>>(&contents) {
                return entries
                    .into_iter()
                    .filter(|e| std::path::Path::new(&e.path).exists())
                    .collect();
            }
        }
    }
    vec![]
}

fn save_vault_registry(entries: &[VaultEntry]) {
    let path = get_registry_path();
    let Ok(json) = serde_json::to_string_pretty(entries) else {
        return;
    };

    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);

    #[cfg(unix)]
    opts.mode(0o600);

    if let Ok(mut file) = opts.open(path) {
        let _ = file.write_all(json.as_bytes());
    }
}

pub fn register_vault(path_str: &str) {
    let name = std::path::Path::new(path_str)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path_str.to_string());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut entries = load_vault_registry();
    if let Some(entry) = entries.iter_mut().find(|e| e.path == path_str) {
        entry.last_opened = now;
        entry.name = name;
    } else {
        entries.push(VaultEntry {
            name,
            path: path_str.to_string(),
            last_opened: now,
        });
    }
    entries.sort_by(|a, b| b.last_opened.cmp(&a.last_opened));
    save_vault_registry(&entries);
}

pub fn remove_vault_from_registry(path_str: &str) {
    let mut entries = load_vault_registry();
    entries.retain(|e| e.path != path_str);
    save_vault_registry(&entries);
}
