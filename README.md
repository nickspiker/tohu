# tohu

**Device identity for the passless app stack.**

*tohu* (תֹּהוּ, Hebrew): the formless — primordial void and chaos, randomness before it takes shape. *tohu* (Māori): a sign, a mark, a proof. The crate is the passage between the two senses: it takes the device's formless randomness — the high-entropy root the platform yields up (ANDROID_ID, machine-id, a firmware UUID) — and draws from it one stable **sign**: the keys and attestations this device answers with. Chaos in, a fixed mark out.

---

## Two layers

tohu is one small crate with two cleanly separated halves:

- **The device oracle** (`device`, `std` only) — reads the strongest device-bound fact each platform allows and returns it as a 32-byte `device_secret`. This is the part that varies by platform, and the only part hardware (PIPE) later replaces.
- **The frozen derivation** (`handle_seed`, `vault_path_name`, `vault_anchor_key`, `attest_with` — pure, `no_std`) — turns a handle plus a `device_secret` into per-app, per-handle, per-device material. `pipe` is the bitwise 256-in / 256-out interface hardware later replaces verbatim: non-zero challenge → attestation, all-zeros → health report. The version suffix (`v0`) is baked into every context string; bumping it is a coordinated migration across every app in the stack.

```text
  handle (any Unicode string)
    │  NFC normalize → BLAKE3
    ▼
  handle_seed (32 bytes)            device_secret (32 bytes, from `device`)
    │                                 │
    └──────────────┬──────────────────┘
                   ▼
   vault_path_name(app_id, handle_seed, device_secret) → 43-char base64url filename
   vault_anchor_key(app_id, handle_seed, device_secret) → 32-byte key
```

Every app in the stack (Photon, Lumis, …) embeds tohu, passes its own constant `app_id`, and derives material no other app or device can reproduce.

---

## The device oracle

`device_secret = BLAKE3(machine_fingerprint())`. The fingerprint per platform:

| Platform | Source | Notes |
|----------|--------|-------|
| Linux    | `/etc/machine-id` | per-install |
| Windows  | registry `MachineGuid` | per-install |
| macOS    | `IOPlatformUUID` | firmware — survives reinstall |
| Android  | `Settings.Secure.ANDROID_ID` via JNI | per-(device, user, app-signing-key) |
| other    | `/etc/hostid`, else `/etc/hostname` | best effort |

**Nothing here opens a socket.** Desktop reads a file or firmware fact; Android reads ANDROID_ID over JNI. The crate's entire dependency list is `blake3`, `unicode-normalization`, `base64`, and `jni` (Android only) — none of which can reach the network. "tohu cannot exfiltrate your identity" is therefore something you can *verify by inspection*, not a promise you have to trust.

### Android

Android denies native code a stable hardware identifier, so the unique value (`ANDROID_ID`) lives behind a Java API. tohu reads it itself — hand it the `JavaVM` once from your `JNI_OnLoad`, and it resolves the application `Context` via `ActivityThread.currentApplication()` (no Java-side change required):

```rust
// in your #[no_mangle] JNI_OnLoad:
tohu::device::android_init(vm);
```

---

## Usage

```rust
let handle_seed = tohu::handle_seed("alice");
let device_secret = tohu::device::device_secret()?;            // platform oracle
let path = tohu::vault_path_name("photon", &handle_seed, &device_secret);
let key  = tohu::vault_anchor_key("photon", &handle_seed, &device_secret);

// PIPE / injected / test: skip the platform read, hash a value you already have
let device_secret = tohu::device::device_secret_from(&raw_bytes);
```

### `pipe` — the 256-in / 256-out interface

`pipe(challenge) -> [u8; 32]` is the narrow waist, deliberately **bitwise 256-in / 256-out** to match the PIPE wire exactly. It is **the one function hardware replaces**: swap its body for a real PIPE transaction and every caller is unchanged. The caller assembles whatever it wants bound to the device (signing identity, a challenge, a file hash) and hashes it to 32 bytes *first*; tohu only appends `device_secret` and never inspects the input or holds a key.

```rust
let challenge: [u8; 32] = blake3::hash(&assembled_payload).into();  // caller-side: domain, pubkey, payload → 256 bits
let proof = tohu::pipe(&challenge)?;                  // software emulation today; passes to PIPE silicon later
let proof = tohu::attest_with(&challenge, &device_secret);         // pure / no_std attest core
```

Today the attest path is `BLAKE3.derive_key("tohu-attest-v0", challenge ‖ device_secret)`; with PIPE present it's a pass-through to the chip. Either way the secret stays on the device.

### Health check — the all-zeros challenge

A challenge of all zeros ([`HEALTH_CHALLENGE`]) is reserved: `pipe` returns a **health report** instead of an attestation — no secret touched, no identity revealed. A real challenge is a BLAKE3 output, so it hits the sentinel only at 2⁻²⁵⁶ (never), which is what makes the overload safe.

```rust
let health = tohu::decode_health(&tohu::pipe(&tohu::HEALTH_CHALLENGE)?);
// software emulator → HealthState { ready: true, hardware: false, slots: 1, rings_online: 0 }
// "dead but responsive": no silicon, but the interface answers.
```

`hardware: false` is the bit an app keys its **Security** posture on — software root vs. hardware root — so the same health check that says "ready" today flips that posture to high the day a real PIPE answers, with no caller change.

---

## Uniqueness

`device_secret` carries exactly the oracle's entropy. `ANDROID_ID` is 64-bit, so an accidental two-device collision is birthday-bound at ~5 billion installs (`√(2·2⁶⁴·ln 2)`) — more than every Android device on Earth, and well past where hardware identity supersedes this oracle. And the provided derivations (`vault_path_name` / `vault_anchor_key`) fold `handle_seed` in regardless, so identities separate by handle even then. Not a concern at realistic scale; the collision-free root is hardware.

---

## Status

`v0` — the derivation primitives are frozen (a snapshot test guards them: if any output shifts, every existing vault on every device becomes unreachable). The device oracle is an interim; the endgame is a hardware identity device, slotted in behind the same `device_secret` boundary with no change to callers.

## License

MIT OR Apache-2.0, at your option.
