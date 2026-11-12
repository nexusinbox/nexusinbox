//! The key passphrase in the macOS login keychain, for starting at login
//! without anyone typing it (docs/39). Opt-in per agent: the stack script's
//! `autostart on` stores it, `autostart off` deletes it.
//!
//! The item is created by this program, so macOS lets this program read it
//! without asking and asks before any other program (the `security`
//! command included) gets it. A new build (e.g. after `brew upgrade`) is a
//! different program to macOS, which then asks once.

/// Keychain service name of the stored passphrases; the account is the
/// credential ID, one item per connected agent.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub const SERVICE: &str = "ai.nexusinbox.signer";

#[cfg(target_os = "macos")]
pub fn store(account: &str, passphrase: &str) -> Result<(), String> {
    security_framework::passwords::set_generic_password(SERVICE, account, passphrase.as_bytes())
        .map_err(|e| format!("could not save the passphrase in the keychain: {e}"))
}

#[cfg(target_os = "macos")]
pub fn load(account: &str) -> Result<String, String> {
    let bytes = security_framework::passwords::get_generic_password(SERVICE, account)
        .map_err(|e| format!("could not read the passphrase from the keychain: {e}"))?;
    String::from_utf8(bytes).map_err(|_| "the stored passphrase is not text".to_string())
}

#[cfg(target_os = "macos")]
pub fn delete(account: &str) -> Result<(), String> {
    match security_framework::passwords::delete_generic_password(SERVICE, account) {
        Ok(()) => Ok(()),
        // Nothing stored is fine: the goal is that nothing is stored.
        Err(e) if e.code() == -25300 => Ok(()), // errSecItemNotFound
        Err(e) => Err(format!(
            "could not delete the passphrase from the keychain: {e}"
        )),
    }
}

#[cfg(not(target_os = "macos"))]
pub fn store(_account: &str, _passphrase: &str) -> Result<(), String> {
    Err("starting at login with a stored passphrase is macOS only for now (docs/39)".into())
}

#[cfg(not(target_os = "macos"))]
pub fn load(_account: &str) -> Result<String, String> {
    Err("reading the passphrase from a keychain is macOS only for now (docs/39)".into())
}

#[cfg(not(target_os = "macos"))]
pub fn delete(_account: &str) -> Result<(), String> {
    Err("the keychain is macOS only for now (docs/39)".into())
}
