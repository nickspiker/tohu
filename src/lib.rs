//! tohu — device identity for the TOKEN/FGTW app stack. The sign (Māori *tohu*) drawn from the formless (Hebrew *tohu*): a stable, device-bound secret read from the platform, then frozen v0 key derivation on top.
//!
//! Two layers:
//!   * [`device`] (std only) — the per-platform device oracle. Reads the strongest device-bound fact each platform allows and returns it as `device_secret`. Desktop reads a firmware/install fact directly; Android reads `Settings.Secure.ANDROID_ID` itself via a JavaVM + Context the app hands in once ([`device::android_init`]). No networking on any platform — auditable by inspection. This is the seam PIPE slots into later: swap the source, the derivation below is untouched.
//!   * the frozen derivation primitives ([`handle_seed`], [`vault_path_name`], [`vault_anchor_key`], [`attest_with`]) — pure, `no_std`. Every app in the stack (Photon, Lumis, ...) derives its own per-user per-device material from these. [`pipe`] is the bitwise 256-in / 256-out interface that mirrors the PIPE wire and that hardware later replaces verbatim: a non-zero challenge attests (binds the input to the device), and the all-zeros [`HEALTH_CHALLENGE`] returns a [`HealthState`] (`hardware: false` under software emulation). The version suffix (`v0`) is baked into every context string; bumping requires a coordinated stack migration.
//!
//! # Pipeline
//!
//! ```text
//!   handle (plaintext String, any Unicode)
//!     │  VSF x encode (NFC + full-codespace Huffman) → BLAKE3
//!     ▼
//!   handle_seed (32 bytes)
//!     │
//!     ├─→ vault_path_name(app_id, handle_seed, device_secret) → base64url filename
//!     └─→ vault_anchor_key(app_id, handle_seed, device_secret) → 32-byte key
//! ```
//!
//! `handle_seed` is the cheap deterministic root of all local derivation. Anyone with the handle string can recompute it; not safe to publish. `device_secret` is the 32-byte hash of [`device::machine_fingerprint`] — produced here in [`device`], never leaving the device.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::String;

/// Frozen version suffix. Every context string in this crate ends with this. Bumping to `v1` means a coordinated migration across all stack apps.
pub const VERSION: &str = "v0";

/// Cheap, deterministic 32-byte seed derived from a handle string. VSF x-encodes the handle (NFC normalization + full-codespace Huffman) then BLAKE3-hashes the resulting bytes — identical canonicalization to `ihi::handle_to_hash`, so vault_seed and identity_seed share one pre-image contract. The VSF frozen encoder lane (vsf "0.6") is pinned so the byte stream can never shift under this derivation.
///
/// **Not** the public network identity — that's `handle_proof` (the memory-hard PoW). This is the cheap derivation root for local material only.
pub fn handle_seed(handle: &str) -> [u8; 32] {
    let vsf_bytes = vsf::types::VsfType::x(String::from(handle)).flatten();
    *blake3::hash(&vsf_bytes).as_bytes()
}

/// Per-app per-handle per-device opaque vault filename. Output is a 43-character base64url string (no padding). `app_id` is a constant string the calling app embeds at build time (e.g. `"photon"`, `"lumis"`).
///
/// Anyone with all three inputs can recompute the filename. Anyone missing any one of them cannot — including someone with the handle but on a different device, or on the same device but probing for a different app.
pub fn vault_path_name(
    app_id: &str,
    handle_seed: &[u8; 32],
    device_secret: &[u8; 32],
) -> String {
    let context = derive_context("vault-path", app_id);
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(handle_seed);
    ikm[32..].copy_from_slice(device_secret);
    let addr: [u8; 32] = blake3::derive_key(&context, &ikm);
    base64url_encode(&addr)
}

/// Per-app per-handle per-device anchor key. Used as the root for vault encryption keys / record-level AEAD keys.
pub fn vault_anchor_key(
    app_id: &str,
    handle_seed: &[u8; 32],
    device_secret: &[u8; 32],
) -> [u8; 32] {
    let context = derive_context("vault-anchor", app_id);
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(handle_seed);
    ikm[32..].copy_from_slice(device_secret);
    blake3::derive_key(&context, &ikm)
}

/// Device-bound attestation — the bitwise **256-in / 256-out** transform that mirrors the PIPE wire exactly. `input` is a 256-bit value the caller has already assembled (domain, pubkey, payload — whatever it wants bound — hashed to 32 bytes *before* it gets here). tohu only appends `device_secret`; it never inspects `input`, does no domain handling of its own (that's the caller's job), and holds no key. Because the shape is identical to PIPE's, a hardware root drops in with **no translation**: the same 32 bytes go to silicon and 32 come back.
///
/// Today (software emulation) the response is `BLAKE3.derive_key("tohu-attest-v0", input ‖ device_secret)` — the fixed context separates attestations from vault keys; the secret's 32-byte tail keeps the split unambiguous. With PIPE present this becomes a pass-through to the chip. See [`attest`] for the std form that reads `device_secret` from the platform oracle.
pub fn attest_with(input: &[u8; 32], device_secret: &[u8; 32]) -> [u8; 32] {
    let context = derive_context("attest", "tohu"); // "tohu-attest-v0"
    let mut hasher = blake3::Hasher::new_derive_key(&context);
    hasher.update(input);
    hasher.update(device_secret);
    *hasher.finalize().as_bytes()
}

/// The reserved HEALTH challenge: passing all-zeros to [`pipe`] requests a health report instead of an attestation. A real challenge is a BLAKE3 output, so it equals this sentinel only at probability 2^-256 — i.e. never — which is what makes overloading the single 256→256 function safe. Health touches no secret and reveals no identity; it only reports what kind of pipe is answering.
pub const HEALTH_CHALLENGE: [u8; 32] = [0u8; 32];

const HEALTH_VERSION: u8 = 0;
const HEALTH_FLAG_READY: u8 = 0b0000_0001;
const HEALTH_FLAG_HARDWARE: u8 = 0b0000_0010;

/// Chip vitality on PIPE's two-bit redundancy scale (see ferros `GLOSSARY.md`), the value rising with attesting capability. NGARO — silent failure — has no code here: a NGARO chip does not transmit, so the caller infers it from [`pipe`] returning no response (`Err` / timeout), never from a decoded vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ChipState {
    /// KORE (`00`) — pre-provisioning void: no *ira* burned, no identity.
    Kore = 0b00,
    /// WHARA (`01`) — two redundancy pairs valid, two invalid: minimum byzantine quorum.
    Whara = 0b01,
    /// HARA (`10`) — three pairs valid, one invalid: single-fault tolerated.
    Hara = 0b10,
    /// ORA (`11`) — all four pairs valid: fully operational. Software emulation reports ORA with `hardware: false` — operational, but no silicon redundancy (see `slots` / `rings_online`).
    Ora = 0b11,
}

impl ChipState {
    fn from_code(code: u8) -> Self {
        match code & 0b11 {
            0b00 => ChipState::Kore,
            0b01 => ChipState::Whara,
            0b10 => ChipState::Hara,
            _ => ChipState::Ora,
        }
    }
}

/// What a [`pipe`] health report decodes to. The software emulator reports the silicon as absent — "operational but emulated": [`ChipState::Ora`] (it answers attestations) yet `hardware: false`, a single slot, no redundancy, zero rings online. Real PIPE fills these from the chip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HealthState {
    /// The pipe is responsive and will answer attestations. `false` paired with no wire response is NGARO (see [`ChipState`]).
    pub ready: bool,
    /// `true` = backed by real PIPE silicon; `false` = software emulation (tohu). This is the bit an app keys its "Security" posture on: hardware root vs software root.
    pub hardware: bool,
    /// The chip's vitality on the [`ChipState`] scale. Software emulation reports [`ChipState::Ora`].
    pub state: ChipState,
    /// Redundancy slots: 1 in software; the chip's slot count in hardware.
    pub slots: u8,
    /// Rings currently online: 0 in software (no rings); the chip's live-ring count in hardware.
    pub rings_online: u8,
}

/// The emulated software health vector — a fixed 32-byte packed state ([`decode_health`] reads it back), the same layout real PIPE fills from the chip. Byte 0 is the version; byte 1 the flags (READY, HARDWARE); byte 2 the slot count; byte 3 the live-ring count; byte 4 the [`ChipState`] code. Identical on every software install: it describes the *kind* of pipe (software, ready, ORA-but-emulated), never the device.
pub fn health_vector() -> [u8; 32] {
    let mut v = [0u8; 32];
    v[0] = HEALTH_VERSION;
    v[1] = HEALTH_FLAG_READY; // ready; hardware bit clear = software emulation
    v[2] = 1; // one slot
    v[3] = 0; // zero rings online
    v[4] = ChipState::Ora as u8; // operational (no silicon redundancy; hardware bit clear says so)
    v
}

/// Decode a health response (from [`pipe`] with [`HEALTH_CHALLENGE`]) into a [`HealthState`].
pub fn decode_health(resp: &[u8; 32]) -> HealthState {
    HealthState {
        ready: resp[1] & HEALTH_FLAG_READY != 0,
        hardware: resp[1] & HEALTH_FLAG_HARDWARE != 0,
        state: ChipState::from_code(resp[4]),
        slots: resp[2],
        rings_online: resp[3],
    }
}

/// The PIPE interface — a bitwise 256-in / 256-out transform, and **the one function hardware replaces**: swap this body for a real PIPE transaction and every caller (Photon, ...) is unchanged.
///
/// `challenge` == [`HEALTH_CHALLENGE`] (all zeros) → a health report ([`decode_health`]); the device secret is not touched. Any other `challenge` → an attestation: `device_secret` is appended ([`attest_with`]) and 256 bits come back. Reads the secret from the platform oracle ([`device::device_secret`]) today; from the kernel / silicon under ferros / PIPE.
#[cfg(feature = "std")]
pub fn pipe(challenge: &[u8; 32]) -> std::io::Result<[u8; 32]> {
    if *challenge == HEALTH_CHALLENGE {
        return Ok(health_vector());
    }
    Ok(attest_with(challenge, &device::device_secret()?))
}

// ── Session handle — the device's one handle, shared in RAM (std) ─────────────────────────
//
// The SESSION backend from `docs/handle.md`: the device's single identity, held in the per-login RAM-backed runtime dir so every app the user runs reads the same one, it survives an app restart, and it dies at logout — never on durable disk.
//
// It stores fixed-size DERIVED ROOTS, never the handle string. The string is variable-length (no register holds it) and the user's plaintext handle need never live anywhere; an app computes the roots from the typed handle once, at first attest, and drops the string. See [`SessionIdentity`].
//
// First cut: an `$XDG_RUNTIME_DIR` (tmpfs) file — shared across the user's session, gone at logout. Honest wart: tmpfs can swap, so it's RAM-but-not-swap-proof; the swap-resistant upgrade is the kernel session keyring (no daemon). There is deliberately no agent daemon — on a shared-UID OS a daemon adds nothing over the keyring (a same-UID process reads either), and hardware (PIPE) is the only same-UID-proof store. Non-unix falls back to the temp dir (functional, not RAM) until each platform's native session store lands.

/// The device's session identity — fixed-size derived roots, register-shaped. The handle string is never stored: it is variable-length (no register would hold it) and the plaintext need not exist outside the moment of first attest. All three are 256-bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct SessionIdentity {
    /// The network/contacts/avatar root — the app's pre-PoW handle hash (e.g. `ihi::handle_to_hash`). Secret.
    pub identity_seed: [u8; 32],
    /// The local-vault root — [`handle_seed`], kept on a SEPARATE pre-image from `identity_seed` so a `handle_proof` observed on the wire has no derivation path (not even one-way) to the vault key. Secret.
    pub vault_seed: [u8; 32],
    /// The public memory-hard proof (`spaghettify(identity_seed)`). Safe on the wire; cached here so resume skips the ~1s recompute.
    pub handle_proof: [u8; 32],
}

/// The device's remembered session identity for this login, or `None` (first run, after logout, or [`clear_session`]). Every app the user runs reads this, so they share one identity without each re-prompting — and without the handle string ever touching the store.
#[cfg(feature = "std")]
pub fn session() -> Option<SessionIdentity> {
    let bytes = std::fs::read(session_path()?).ok()?;
    if bytes.len() != 96 {
        return None;
    }
    let mut s = SessionIdentity::default();
    s.identity_seed.copy_from_slice(&bytes[0..32]);
    s.vault_seed.copy_from_slice(&bytes[32..64]);
    s.handle_proof.copy_from_slice(&bytes[64..96]);
    Some(s)
}

/// Remember the session identity (RAM, `0600` on unix, gone at logout). Overwrites any prior value. Writes the three roots as 96 raw bytes — no handle string.
#[cfg(feature = "std")]
pub fn set_session(s: &SessionIdentity) -> std::io::Result<()> {
    use std::io::Write;
    let path = session_path()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no session runtime dir"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&path)?;
    f.write_all(&s.identity_seed)?;
    f.write_all(&s.vault_seed)?;
    f.write_all(&s.handle_proof)
}

/// Forget the session identity (logout / drop). The runtime dir is wiped by the OS at logout regardless.
#[cfg(feature = "std")]
pub fn clear_session() {
    if let Some(p) = session_path() {
        let _ = std::fs::remove_file(p);
    }
}

#[cfg(feature = "std")]
fn session_path() -> Option<std::path::PathBuf> {
    use std::path::PathBuf;
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| {
            let user = std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_else(|_| String::from("user"));
            std::env::temp_dir().join(format!("tohu-{user}"))
        });
    Some(base.join("tohu").join("session"))
}

fn derive_context(role: &str, app_id: &str) -> String {
    let mut s = String::with_capacity(app_id.len() + role.len() + VERSION.len() + 2);
    s.push_str(app_id);
    s.push('-');
    s.push_str(role);
    s.push('-');
    s.push_str(VERSION);
    s
}

fn base64url_encode(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The per-platform device oracle and `device_secret` (std only). The source of the device fact is the only thing that varies by platform — and the only thing PIPE later replaces; the derivation above is identical everywhere.
///
/// Nothing here opens a socket. Desktop reads a file / firmware fact; Android reads `Settings.Secure.ANDROID_ID` over JNI. Both local. The crate's deps (blake3, unicode-normalization, base64, and jni on Android only) contain nothing that can reach the network, so "tohu cannot exfiltrate your identity" is verifiable from the dependency list, not asserted.
///
/// UNIQUENESS — `device_secret` carries the oracle's entropy. `ANDROID_ID` is 64-bit, so an accidental two-device collision is birthday-bound at ~5 billion installs — past every Android device on Earth, and past where hardware identity supersedes this oracle. And the provided derivations ([`vault_path_name`] / [`vault_anchor_key`]) fold `handle_seed` in regardless, so identities separate by handle even then. Not a concern at realistic scale; the collision-free root is hardware (PIPE).
#[cfg(feature = "std")]
pub mod device {
    use std::io;
    use std::vec::Vec;

    /// 32-byte device-bound secret: `BLAKE3(machine_fingerprint())`. The root every stack app feeds to [`super::vault_path_name`] / [`super::vault_anchor_key`] (and, in photon, the FGTW device-keypair seed).
    pub fn device_secret() -> io::Result<[u8; 32]> {
        Ok(*blake3::hash(&machine_fingerprint()?).as_bytes())
    }

    /// `BLAKE3(raw)` — for callers that obtain the device fact another way (PIPE hardware, an injected value, tests). Same hash step as [`device_secret`].
    pub fn device_secret_from(raw: &[u8]) -> [u8; 32] {
        *blake3::hash(raw).as_bytes()
    }

    /// The raw platform device fact (hashed into [`device_secret`]):
    /// Linux `/etc/machine-id` · Windows registry `MachineGuid` · macOS `IOPlatformUUID` (firmware, survives reinstall) · Android `Settings.Secure.ANDROID_ID` via JNI (needs [`android_init`]) · other: `/etc/hostid` then `/etc/hostname`.
    #[cfg(target_os = "linux")]
    pub fn machine_fingerprint() -> io::Result<Vec<u8>> {
        std::fs::read("/etc/machine-id")
    }

    #[cfg(target_os = "windows")]
    pub fn machine_fingerprint() -> io::Result<Vec<u8>> {
        use std::process::Command;
        let output = Command::new("reg")
            .args([
                "query",
                "HKLM\\SOFTWARE\\Microsoft\\Cryptography",
                "/v",
                "MachineGuid",
            ])
            .output()?;
        Ok(output.stdout)
    }

    #[cfg(target_os = "macos")]
    pub fn machine_fingerprint() -> io::Result<Vec<u8>> {
        use std::process::Command;
        // Extract ONLY IOPlatformUUID; the full ioreg block carries dynamic fields (addresses, timestamps) that change run to run.
        let output = Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("IOPlatformUUID") {
                if let Some(start) = line.rfind('"') {
                    if let Some(end) = line[..start].rfind('"') {
                        let uuid = &line[end + 1..start];
                        if uuid.len() > 8 {
                            return Ok(uuid.as_bytes().to_vec());
                        }
                    }
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "IOPlatformUUID not found",
        ))
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "windows",
        target_os = "macos",
        target_os = "android"
    )))]
    pub fn machine_fingerprint() -> io::Result<Vec<u8>> {
        if let Ok(hostid) = std::fs::read("/etc/hostid") {
            return Ok(hostid);
        }
        Ok(std::fs::read("/etc/hostname").unwrap_or_else(|_| b"unknown".to_vec()))
    }

    #[cfg(target_os = "android")]
    pub fn machine_fingerprint() -> io::Result<Vec<u8>> {
        android::android_id()
    }

    #[cfg(target_os = "android")]
    pub use android::android_init;

    // NEEDS ON-DEVICE TEST: this path only compiles under an android target and only runs on a device — it has NOT been executed. JNI calls target jni 0.21. The app `Context` is fetched via `ActivityThread.currentApplication()` so no Java-side change is needed; the only thing the app must do is hand tohu the JavaVM once via [`android_init`] (from its `JNI_OnLoad`). Build the APK to compile-verify before relying on it.
    #[cfg(target_os = "android")]
    mod android {
        use jni::objects::{JString, JValue};
        use jni::JavaVM;
        use std::io;
        use std::string::{String, ToString};
        use std::sync::OnceLock;
        use std::vec::Vec;

        static VM: OnceLock<JavaVM> = OnceLock::new();

        /// Hand tohu the `JavaVM` once at startup (call from the app's `JNI_OnLoad`, where the vm is handed to you). Required for [`super::machine_fingerprint`] on Android — the app `Context` is then resolved internally via `ActivityThread.currentApplication()`. First call wins.
        pub fn android_init(vm: JavaVM) {
            let _ = VM.set(vm);
        }

        /// `Settings.Secure.getString(ActivityThread.currentApplication().getContentResolver(), "android_id")`.
        pub fn android_id() -> io::Result<Vec<u8>> {
            let vm = VM.get().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "tohu::device::android_init(vm) must be called (from JNI_OnLoad) before machine_fingerprint on Android",
                )
            })?;
            let mut env = vm.attach_current_thread().map_err(jerr)?;
            // Application context without a Java-side handoff.
            let app = env
                .call_static_method(
                    "android/app/ActivityThread",
                    "currentApplication",
                    "()Landroid/app/Application;",
                    &[],
                )
                .and_then(|v| v.l())
                .map_err(jerr)?;
            if app.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "ActivityThread.currentApplication() returned null (called before Application onCreate?)",
                ));
            }
            let resolver = env
                .call_method(
                    &app,
                    "getContentResolver",
                    "()Landroid/content/ContentResolver;",
                    &[],
                )
                .and_then(|v| v.l())
                .map_err(jerr)?;
            let name = env.new_string("android_id").map_err(jerr)?;
            let value = env
                .call_static_method(
                    "android/provider/Settings$Secure",
                    "getString",
                    "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;",
                    &[JValue::Object(&resolver), JValue::Object(&name)],
                )
                .and_then(|v| v.l())
                .map_err(jerr)?;
            let s: String = env.get_string(&JString::from(value)).map_err(jerr)?.into();
            Ok(s.into_bytes())
        }

        fn jerr(e: jni::errors::Error) -> io::Error {
            io::Error::new(io::ErrorKind::Other, e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_seed_nfc_equivalence() {
        let precomposed = handle_seed("café");
        let decomposed = handle_seed("cafe\u{0301}");
        assert_eq!(precomposed, decomposed, "NFC must collapse to same seed");
    }

    #[test]
    fn handle_seed_distinguishes_case() {
        assert_ne!(handle_seed("Alice"), handle_seed("alice"), "NFC does not case-fold");
    }

    #[test]
    fn vault_path_name_app_separation() {
        let seed = handle_seed("alice");
        let device = [0x42u8; 32];
        let photon = vault_path_name("photon", &seed, &device);
        let lumis = vault_path_name("lumis", &seed, &device);
        assert_ne!(photon, lumis, "different app_ids must yield different paths");
    }

    #[test]
    fn vault_path_name_device_separation() {
        let seed = handle_seed("alice");
        let a = vault_path_name("photon", &seed, &[0x42u8; 32]);
        let b = vault_path_name("photon", &seed, &[0x43u8; 32]);
        assert_ne!(a, b, "different device_secrets must yield different paths");
    }

    #[test]
    fn vault_path_name_handle_separation() {
        let device = [0x42u8; 32];
        let a = vault_path_name("photon", &handle_seed("alice"), &device);
        let b = vault_path_name("photon", &handle_seed("bob"), &device);
        assert_ne!(a, b, "different handles must yield different paths");
    }

    #[test]
    fn vault_anchor_key_role_separation() {
        // Same inputs, different role → different output (vault-path vs vault-anchor)
        let seed = handle_seed("alice");
        let device = [0x42u8; 32];
        let path_bytes = {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
            URL_SAFE_NO_PAD.decode(vault_path_name("photon", &seed, &device)).unwrap()
        };
        let anchor = vault_anchor_key("photon", &seed, &device);
        assert_ne!(path_bytes.as_slice(), anchor.as_slice(), "different roles must derive different bytes");
    }

    #[test]
    fn vault_path_name_format() {
        let path = vault_path_name("photon", &handle_seed("alice"), &[0u8; 32]);
        assert_eq!(path.len(), 43, "32 bytes base64url no-pad → 43 chars");
        assert!(path.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    /// Snapshot test: if any of these fail, the v0 derivation has shifted and every existing vault on every device is now unreachable. Either revert the change or bump to v1 with a coordinated stack migration.
    #[test]
    fn snapshot_v0() {
        let seed = handle_seed("alice");
        let device = [0xAAu8; 32];

        assert_eq!(
            hex::encode(seed),
            "e450d4112116ee2d7ee2388cfcf1b4ad39399be7e31b57839be0d9a8de0dbdde",
            "handle_seed(\"alice\") shifted",
        );
        assert_eq!(
            vault_path_name("photon", &seed, &device),
            "ak2ZJo3J5u7LII8RDplU-jmascCgevi5T24GvYvBW-Q",
            "vault_path_name shifted",
        );
        assert_eq!(
            hex::encode(vault_anchor_key("photon", &seed, &device)),
            "af52ecc6d9883732bacfcc9114a5938dd2d8e117fdcba037c8c3d500787b218f",
            "vault_anchor_key shifted",
        );
        assert_eq!(
            hex::encode(attest_with(&[0x11u8; 32], &device)),
            "7e3c1e1ad504a78f43181585b0f1c38ba21a2ffe3f7bd582020058e20efbe94f",
            "attest_with shifted",
        );
        assert_eq!(
            hex::encode(health_vector()),
            "0001010003000000000000000000000000000000000000000000000000000000",
            "health_vector shifted",
        );
    }

    #[test]
    fn health_decodes_software_state() {
        let h = decode_health(&health_vector());
        assert!(h.ready, "emulator is responsive");
        assert!(!h.hardware, "emulator must report NO hardware (drives Security posture)");
        assert_eq!(h.state, ChipState::Ora, "software emulation is operational (ORA), no silicon redundancy");
        assert_eq!(h.slots, 1, "software is a single slot");
        assert_eq!(h.rings_online, 0, "software has zero rings online");
    }

    #[test]
    fn health_decodes_hardware_flag() {
        // A future hardware vector with both flags set decodes as ready + hardware.
        let mut v = health_vector();
        v[1] |= HEALTH_FLAG_HARDWARE;
        let h = decode_health(&v);
        assert!(h.ready && h.hardware);
    }

    #[test]
    fn pipe_health_challenge_returns_health() {
        // The all-zeros challenge returns the health vector, NOT an attestation, and never touches the oracle.
        assert_eq!(
            pipe(&HEALTH_CHALLENGE).unwrap(),
            health_vector(),
            "all-zeros challenge must be the health check",
        );
    }

    #[test]
    fn attest_separation_and_determinism() {
        let device = [0x42u8; 32];
        let input = [0x11u8; 32];
        // Deterministic: same 256-bit input + secret → same 256-bit output.
        assert_eq!(
            attest_with(&input, &device),
            attest_with(&input, &device),
            "attest must be deterministic",
        );
        // Input sensitivity.
        assert_ne!(
            attest_with(&[0x01u8; 32], &device),
            attest_with(&[0x02u8; 32], &device),
            "different inputs must differ",
        );
        // Device binding.
        assert_ne!(
            attest_with(&input, &[0x42u8; 32]),
            attest_with(&input, &[0x43u8; 32]),
            "different device_secrets must differ",
        );
    }
}
