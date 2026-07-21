use nix::sys::termios::{LocalFlags, SetArg, tcgetattr, tcsetattr};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::io::AsFd;
use zeroize::Zeroizing;

/// Directly reads from TTY, locking buffer in RAM to prevent swap leaks,
/// and disabling core dumps for the memory region.
pub fn read_password_pinentry() -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    // 1. Bind to TTY directly (bypasses stdin redirection)
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| format!("Security Error: Could not bind to secure TTY: {}", e))?;

    // 2. Disable terminal echo
    // BORROW CHECKER FIX: as_fd() is called inline, borrowing tty only for this exact line.
    let mut termios = tcgetattr(tty.as_fd())?;
    let original_termios = termios.clone();
    termios.local_flags.remove(LocalFlags::ECHO);
    tcsetattr(tty.as_fd(), SetArg::TCSANOW, &termios)?;

    // 3. Allocate fixed buffer and lock in physical RAM
    let mut buffer = [0u8; 128];
    unsafe {
        // Lock page in physical RAM (No Swap)
        if libc::mlock(buffer.as_mut_ptr() as *const libc::c_void, buffer.len()) != 0 {
            let _ = tcsetattr(tty.as_fd(), SetArg::TCSANOW, &original_termios); // Restore on fail
            return Err("Fatal: Failed to lock memory page via mlock".into());
        }
        // Prevent core dumps for this specific region
        libc::madvise(
            buffer.as_mut_ptr() as *mut libc::c_void,
            buffer.len(),
            libc::MADV_DONTDUMP,
        );
    }

    // 4. Secure Prompt
    // This mutable borrow works now because there is no active immutable borrow hanging around!
    tty.write_all(b"\n[SECURE INPUT] Enter Master Password: ")?;

    let mut idx = 0;
    let mut byte = [0u8; 1];

    // Read char by char
    loop {
        tty.read_exact(&mut byte)?;
        if byte[0] == b'\n' || byte[0] == b'\r' {
            break;
        }
        // Prevent buffer overflow
        if idx < buffer.len() {
            buffer[idx] = byte[0];
            idx += 1;
        }
    }
    tty.write_all(b"\n")?;

    // 5. Restore terminal echo
    tcsetattr(tty.as_fd(), SetArg::TCSANOW, &original_termios)?;

    // 6. Wrap in Zeroizing for safe transport to crypto.rs
    let password = String::from_utf8(buffer[..idx].to_vec())
        .map_err(|_| "Invalid UTF-8 sequence in password")?;

    let secure_password = Zeroizing::new(password);

    // 7. Anti-Forensics: Wipe buffer and unlock memory
    buffer.fill(0);
    unsafe {
        libc::munlock(buffer.as_mut_ptr() as *const libc::c_void, buffer.len());
    }

    Ok(secure_password)
}
