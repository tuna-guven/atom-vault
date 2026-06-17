use landlock::{
    ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, path_beneath_rules,
};
use std::env;
use std::ffi::CString;
use std::os::fd::RawFd;
use std::path::Path;
use std::ptr;
use std::fs::DirBuilder;
use std::os::unix::fs::DirBuilderExt; // Unix izinlerini (0o700) ayarlamak için eklendi

// Zathura'nın PID'sini arka plan thread'ine iletmek üzere geri döndürür
pub fn spawn_in_sandbox(target_fd: RawFd) -> Result<libc::pid_t, Box<dyn std::error::Error + Send + Sync>> {
    let abi = ABI::V7;
    let handled_accesses = AccessFs::from_all(abi);
    
    let mut ruleset = Ruleset::default()
        .handle_access(handled_accesses)?
        .create()?;

    let system_read_access = AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute;
    let system_paths = [
        "/usr",
        "/lib",
        "/lib64",
        "/etc",
        "/var/cache/fontconfig",
        "/tmp",
        "/sys",
    ];
    ruleset = ruleset.add_rules(path_beneath_rules(system_paths, system_read_access))?;

    let gui_rw_access = AccessFs::ReadFile | AccessFs::WriteFile;
    let dir_access = AccessFs::ReadDir | AccessFs::Execute;

    let volatile_rw_access = AccessFs::ReadFile 
        | AccessFs::WriteFile 
        | AccessFs::MakeDir 
        | AccessFs::MakeReg
        | AccessFs::RemoveFile
        | AccessFs::RemoveDir
        | AccessFs::Truncate;

    let mut fake_data_dir_str = String::from("/run/user/1000"); 
    
    if let Ok(xdg_runtime) = env::var("XDG_RUNTIME_DIR") {
        ruleset = ruleset.add_rules(path_beneath_rules([&xdg_runtime], dir_access))?;

        let wayland_socket = format!("{}/wayland-0", xdg_runtime);
        if Path::new(&wayland_socket).exists() {
            ruleset = ruleset.add_rules(path_beneath_rules([wayland_socket], gui_rw_access))?;
        }

        let dconf_dir = format!("{}/dconf", xdg_runtime);
        if Path::new(&dconf_dir).exists() {
            ruleset = ruleset.add_rules(path_beneath_rules([dconf_dir], gui_rw_access))?;
        }

        let atom_volatile_dir = format!("{}/atom_zathura", xdg_runtime);
        
        // --- GÜVENLİK YAMASI: 700 İzinli Klasör Yaratımı ---
        // Sadece ana süreç bu klasöre erişebilir. Zafiyetleri ve izlenmeyi engeller.
        let mut builder = DirBuilder::new();
        builder.recursive(true);
        builder.mode(0o700); 
        let _ = builder.create(&atom_volatile_dir);
        // ---------------------------------------------------

        ruleset = ruleset.add_rules(path_beneath_rules([&atom_volatile_dir], volatile_rw_access))?;
        fake_data_dir_str = atom_volatile_dir; 
    }

    if let Ok(home) = env::var("HOME") {
        let gtk_config = format!("{}/.config/gtk-3.0", home);
        if Path::new(&gtk_config).exists() {
            ruleset = ruleset.add_rules(path_beneath_rules([gtk_config], system_read_access))?;
        }
    }

    let shm_access = AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Truncate;
    ruleset = ruleset.add_rules(path_beneath_rules(["/dev/shm"], shm_access))?;
    ruleset = ruleset.add_rules(path_beneath_rules(["/dev/urandom"], gui_rw_access))?;

    let path = CString::new("/usr/bin/zathura")?;
    let arg0 = CString::new("zathura")?;
    let arg1 = CString::new("-")?; 
    let argv = [arg0.as_ptr(), arg1.as_ptr(), ptr::null()];

    let env_wayland = CString::new(format!("WAYLAND_DISPLAY={}", env::var("WAYLAND_DISPLAY").unwrap_or_else(|_| "wayland-0".into())))?;
    let env_xdg = CString::new(format!("XDG_RUNTIME_DIR={}", env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/run/user/1000".into())))?;
    let env_home = CString::new(format!("HOME={}", env::var("HOME").unwrap_or_else(|_| "/".into())))?;
    let env_display = CString::new(format!("DISPLAY={}", env::var("DISPLAY").unwrap_or_else(|_| ":0".into())))?;
    let env_soft = CString::new("LIBGL_ALWAYS_SOFTWARE=1")?;
    let env_data_home = CString::new(format!("XDG_DATA_HOME={}", fake_data_dir_str))?;
    let env_tmpdir = CString::new(format!("TMPDIR={}", fake_data_dir_str))?;

    let envp = [
        env_wayland.as_ptr(),
        env_xdg.as_ptr(),
        env_home.as_ptr(),
        env_display.as_ptr(),
        env_soft.as_ptr(),
        env_data_home.as_ptr(),
        env_tmpdir.as_ptr(),
        ptr::null(),
    ];

    unsafe {
        match libc::fork() {
            0 => {
                libc::dup2(target_fd, libc::STDIN_FILENO);

                // SECURITY FIX 2: Error logging safely routed to volatile RAM to prevent disk TOCTOU leaks
                let log_path = format!("{}/zathura_debug.log", fake_data_dir_str);
                let err_log = CString::new(log_path).unwrap();
                let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND;
                let log_fd = libc::open(err_log.as_ptr(), flags, 0o644);
                if log_fd >= 0 {
                    libc::dup2(log_fd, libc::STDERR_FILENO);
                }

                libc::lseek(target_fd, 0, libc::SEEK_SET);

                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                    libc::exit(1);
                }

                // Enforce Landlock isolation securely
                if ruleset.restrict_self().is_err() {
                    libc::exit(1);
                }

                // Execute target binary with the fortified volatile environment
                libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
                libc::exit(1);
            }
            pid if pid > 0 => {
                // GUI'yi dondurmamak için waitpid kaldırıldı. PID asenkron thread'e döner.
                Ok(pid)
            }
            _ => return Err("Fork failed".into()),
        }
    }
}
