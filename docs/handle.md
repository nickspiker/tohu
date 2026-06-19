# handle — the device's one identity, broadcast to every app

**Status: design, not yet built.** This layer lives entirely in tohu's `device` half (`std`, does I/O). It does **not** touch the frozen `v0` derivation primitives — no snapshot output shifts, no existing vault moves. It only fills the gap the README leaves open: `handle_seed(handle)` takes a handle as *input* and never says where that handle comes from, or how every app on the device agrees on the same one.

## The gap, and the one rule

A handle is the user's identity — *any Unicode string* — and per Photon's model it is a **shared secret, not a public name**: you give it out-of-band only to people you want to reach you, the network routes on `hash(handle)` and never transmits the string, and learning someone's handle is precisely what lets an attacker target them. So the handle string deserves confidentiality at rest, within the hard limits of the platform (see below). Today each app would have to ask for it separately. That is both annoying and wrong: it invites a different handle per app, which is a sybil hole.

**The rule: one handle per device.** Not per app — per *device*. But be precise about *where that is enforced*, because tohu alone cannot enforce it. The `device_secret`-keyed slot below buys **local coherence**: every honest app on the device reads the same handle, and the tooling holds exactly one. That is not a security boundary — a determined local user can write whatever bytes they like, and `device_secret` is a hash of a machine fact, not a one-handle gate. The actual sybil resistance lives on the **network** (see below): peers refuse to attest a second handle for an already-registered device. tohu's contribution is the unforgeable, machine-rooted attestation (`attest_with` / `pipe`) that the binding is keyed on — producing it, not enforcing uniqueness over it.

## The accessor

Every app already embeds tohu. So the broadcast point is tohu, exposed as one call:

```rust
tohu::handle() -> Option<HandleSeed>   // the device's single handle_seed; None on first run
```

Apps never store, prompt for, or sync the handle themselves. idiosync, Photon, Lumis all do the same thing: `tohu::handle()`, then `vault_anchor_key(app_id, seed, device_secret)`. Sharing the seed shares nothing app-specific — `app_id` domain separation keeps each app's vault unreachable from any other (idiosync cannot derive Photon's keys with the same handle; the BLAKE3 contexts differ).

What is stored is the **seed**, not the string: `handle_seed` is one-way, so even a successful read of the slot yields an irreversible hash, never the chosen handle. A human-readable display name, if an app wants one, is a separate non-secret field — TOKEN's namespace, not tohu's. tohu holds exactly the 32 bytes derivation needs.

## Two backends, chosen by user preference

Persistence is the user's call, and it picks the backend behind the same `handle()` accessor. The axis is latency/persistence: keep it on the medium (survives reboot), or hold it only for the session (re-entered each login, never lands).

```
tohu::handle() resolves against the configured backend:
  persist  → device-encrypted slot on latent storage   (survives reboot)
  session  → best-fit volatile store, re-entered at login (never hits disk)
  neither  → None → app prompts once → write to the chosen backend → broadcast done
```

Either way the *write* is gated on `device_secret`, so "one per device" holds in both — persist just remembers it across reboots; session re-asks at login.

### persist — device-derived filename, device-encrypted contents

Three independent layers, all from `device_secret`:

```
path     = vault_path_name("tohu", handle_seed("handle"), device_secret)
           // the label feeding the FILENAME is the constant "handle" — not the user's
           // handle, which we don't have at bootstrap. The user's seed goes inside.
contents = the user's handle_seed, encrypted under a device_secret-derived key
```

- **device-derived filename** → only this device can *find* the slot.
- **device_secret encryption** → only this device can *read* it even if found — a copied file on another machine cannot derive its own key (the manifestus "leaked file is safe" property, here for one slot).
- **seed not string** → a successful read reveals only an irreversible hash.

On ferros the encryption key *is* the 256-bit hardware register — a register op, no derivation. On Linux/Windows/macOS/Android it's `BLAKE3` over the platform `device_secret`. Same boundary `pipe` already draws: hardware replaces the body, callers unchanged. The filename uses the frozen `vault_path_name`, so it's stable across versions; a `v0` bump relocates it under the same migration rules as every vault.

### session — the seed in RAM, shared, never latent

This is the posture that gives every TOKEN app the shared handle without anything derivable touching disk: entered once per login, held in RAM, read by every process the user runs that session, zeroized at logout. It is the genuinely-more-confidential desktop mode (the at-rest / backup / disk-image / swap attacker gets *nothing*; only a live same-UID process during the session sees it — the unavoidable Unix limit, [below](#confidentiality-of-the-handle--and-what-desktop-cannot-promise)).

**Primary mechanism (desktop): the `tohu` session agent — ssh-agent model.** One per logged-in user. It holds the device's `handle_seed` `mlock`'d in RAM (32 bytes; plus, optionally, the handle *string* for "logged in as ☃" display, also `mlock`'d) and serves it to the user's apps over a local socket. Chosen as *primary*, not fallback, because it is **one codepath that works identically everywhere and is small enough to audit whole** — versus five native-keyring integrations, each with its own quirks. Native keyrings (§ below) are an *optional* per-platform hardening, not the baseline.

```
socket   $XDG_RUNTIME_DIR/tohu/agent.sock  (Linux) · launchd path (macOS) · \\.\pipe\tohu-<sid> (Windows)
         mode 0600, user-owned. Peer authenticated by UID (SO_PEERCRED / LOCAL_PEERCRED / pipe ACL):
         only the same user connects — the trust boundary is the UID, which is the desktop reality anyway.

protocol (framed VSF, minimal):
   Get   { slot_id }        → Seed | NotSet
   Set   { slot_id, seed }  → Ok | AlreadySet     // first-run; first-write-wins, never clobbers (race-safe)
   Clear { slot_id }        → Ok                   // logout / drop
   Health{}                 → { ready }            // mirrors pipe's health: "the RAM store is up"

lifecycle  spawn-on-demand (first `handle()` with no live agent starts one) or a user login unit;
           hold for the session; zeroize the mlock'd seed on Clear, idle-timeout, or exit.
           never written to disk — mlock keeps it out of swap, exit wipes it.
```

`slot_id` is the same device-rooted `handle_slot_id` the persist backend uses (`vault_path_name("tohu", handle_seed("handle"), device_secret)`), so every app addresses the one slot with no negotiation. The agent **centralizes** the seed in a single mlock'd place rather than scattering a copy through every app's heap — one thing to protect, one thing to wipe at logout.

**Why not a copy per app:** the goal is *enter once, all apps see it*. A shared agent gives single-entry, cross-app coherence, and one-shot logout wipe; per-app copies give none of those and more seed-sprawl.

**Per-platform notes**

| Platform | Session store | Notes |
|----------|---------------|-------|
| **Desktop (Linux/macOS/Windows)** | **the tohu agent** | same-UID socket; the primary mechanism above |
| ferros | **processor register** | the endgame: hardware-held, readable by no process at any privilege — no agent, no socket, no same-UID exposure. The agent is the pre-ferros interim, same boundary `pipe` already draws. |
| Android | **bound service, signing-key-gated** | the exception: Android sandboxes apps to *different* UIDs, so a same-UID socket can't reach across them. A foreground service holds the seed and serves it over Binder, gated on the caller's app-signing key (the same per-signing-key identity ANDROID_ID already uses). Where even that is unavailable, an app falls back to its own session copy (re-prompt), losing cross-app sharing but not RAM-only-ness. |
| native keyrings (optional) | Linux session keyring (`KEY_SPEC_SESSION_KEYRING`), macOS Keychain session-ACL, Windows DPAPI session | a *stronger* store where present (kernel/OS-held vs a userspace process), wired behind the same `handle()` accessor as a later optimization — not required for the baseline. |

The invariant across all of them is identical: **the seed lives in RAM, is shared across the user's session, and never lands on disk.** The agent delivers that everywhere on desktop today; the register delivers it without a process on ferros tomorrow.

## Double-write, double-verify — same discipline as the vault, on both backends

Neither backend trusts a single write. The handle slot is mirrored and verified exactly the way manifestus mirrors a block: **write copy A → read it back through the cache bypass and byte-compare → only then write copy B.** On read, verify the seal; on mismatch fall to the mirror and heal on the spot. Where the medium offers two of something (mirror files for persist, a paired keyring/register slot for session), both copies carry it; a torn or scribbled slot reads as corrupt and routes to its twin. A 15ms power cut, a cosmic-ray flip, and a tampered byte all surface as one symptom — a slot whose seal fails — and get one treatment. One handle is small, but it's the root every key on the device descends from, so it earns the vault's paranoia, not less.

## Confidentiality of the handle — and what desktop cannot promise

The handle string is a shared secret, so the goal is to make it hard for an attacker with access to the device (or its storage) to *read it*. Be honest about which attacker each defense actually stops, because file-based crypto cannot stop the one that matters most on desktop.

**What we do, and what it buys:**

- **Store the seed, never the string.** The persisted/broadcast artifact is `handle_seed` (one-way BLAKE3 of the handle). A passive read of the slot yields an irreversible hash, never the human-readable handle — so the attacker can't simply *see* it; they must brute-force. Apps only ever need the seed anyway.
- **Encrypt the seed under `device_secret`.** Stops the *off-device* attacker — a copied slot, a backup, a synced file, a stolen disk image used on another machine — because `device_secret` doesn't travel with the bytes.

**The brute-force caveat, stated plainly.** Handles are human-memorable words, and `handle_seed` is frozen as fast BLAKE3, so the seed-at-rest is dictionary-attackable: a same-machine attacker who reads the seed can grind a wordlist against it cheaply. Seed-not-string raises the bar from *read* to *active guess bounded by handle entropy* — real, but not strong secrecy for a guessable handle. We can't memory-harden `handle_seed` to fix this without breaking frozen `v0`.

**What no file scheme can stop on desktop.** A process running as your UID has your files, your `machine-id`-derived `device_secret`, and therefore every key you can compute — so it can read the slot and grind the seed. This is the Unix model, not a tohu flaw; it's the same limitation manifestus documents ("same-user malware: not defended, and no file-based scheme can"). On Linux/Windows/macOS, at-rest handle secrecy against a same-user adversary is **unachievable by derivation**, full stop. Android gets *partial* protection by luck, not design — the app sandbox and per-signing-key identity wall off other apps — so lean on app-private storage + Keystore there, but don't claim crypto secrecy from it.

**So the posture choice is the answer, and it's the persist/session switch already above:**

- **Persist** trades handle-string confidentiality for not-re-entering: a derivable seed sits at rest, dictionary-attackable by a same-user adversary.
- **Session is the genuinely-more-confidential desktop posture** — nothing derivable is at rest, so the disk-image / backup / at-rest attacker gets *nothing*, and the only remaining exposure is a live same-UID process during the session. Cost: re-enter at login. This is what to recommend to a user who actually cares about handle secrecy on desktop.
- **Hardware is the only place real secrecy lives** regardless of mode: on ferros the wrapping key is the PIPE register, readable by no process at any privilege — the same boundary `device_secret` already hides behind, so the day the silicon answers, the same code gets confidentiality it cannot have on a shared-UID OS today.

A note on UX, since "best experience" pulls against this: storing only the seed means even *you* can't redisplay your handle after entry — fine for a confirm-by-re-entry flow, a problem if an app wants to show "logged in as ☃". Session mode can hold the string in RAM for display during the session and drop it at logout; persist mode should show it at most once at entry and keep only the seed.

## Loss — forgetting the handle burns it, permanently

The handle has no recovery path, and the failure is worse than "you're locked out." Forget your handle and:

- **You lose the identity, and new hardware does not bring it back.** Every key on every device descends from `handle_seed`; without the handle *string* you cannot recompute it. The handle, not the device, is the root — so buying new devices doesn't help.
- **The handle is burned for everyone, forever.** Its `handle_proof` stays bound to your now-unreachable device. You can't re-claim it (you've lost the only input that proves ownership), and the attestation gate stops anyone else from taking it (it checks "already bound?" first — see [uniqueness](#where-uniqueness-is-actually-enforced-out-of-scope-for-tohu)). The name sits occupied in perpetuity by an identity nobody controls.

So the only real protection is **redundancy, not recovery**: hold the handle on **more than one device**. A front-end should push this hard — attest, then *immediately* add a second and third device — so forgetting it in one place is survivable.

### The not-advised escapes (a user's choice)

Some users will trade confidentiality for never-forgetting. tohu makes these *possible* and *clearly discouraged*; a front-end should treat both as advanced, warned options:

- **Store the plain handle behind a user key.** A vault entry holding the *string* (not just the seed), encrypted under a key the user supplies (a passphrase, a hardware token) — the device alone can't read it, but the user can recover their own handle. Not advised: it puts the recoverable string at rest, and the user key becomes one more thing not to lose.
- **System-wide plaintext.** The handle stored unencrypted, device-wide. Worse — any same-UID process reads it (the unavoidable desktop limit), and the handle's entire value is that it *isn't* public. Only defensible behind a hardware secrecy boundary (PIPE) or on a device whose physical access you fully control.

If you do keep a recoverable handle on a device, the safety net for theft is **revocation, not secrecy**: a compromised device is revoked from another of your devices, gated by a K-of-N human anti-theft quorum (custodes). Quick cross-device revocation behind a multi-person trigger — not file crypto — is what makes "I keep my handle on this machine" survivable.

## Where uniqueness is actually enforced (out of scope for tohu)

"One handle per device" is a *network* invariant, and the network already has the machinery: Photon's handle attestation (two human attestations, memory-hard PoW, rate-limited 1/hour/device), with bindings stored in the FGTW DHT and the handle cryptographically bound to the device's key. Nobody attests a second handle for an already-registered device because attesters check first — *that* is the sybil resistance, not the local slot.

tohu's one job at this seam is to make the device side of the binding unforgeable and machine-rooted: the attestation the network binds to should be `attest_with(challenge, device_secret)`, so the "device" in "one handle per device" is the actual hardware root, not a self-asserted key a user can rotate to re-register. The uniqueness check on the network should then key on *that device attestation*, not on the handle — you look up "is this device already bound?" before co-signing a new handle.

What that does **not** give you for free is global consensus: a DHT is discovery and storage, not agreement, so a partition or eclipse can let two registrations briefly disagree. Photon already takes the pragmatic resolution — *first to complete attestation owns it* — and the human-attestation gate (not a ledger) is what makes a forged second binding expensive. Whether to harden that with a witness quorum, or accept first-attested-wins, is a TOKEN/Photon decision; see Photon's `AUTH.md`. tohu only supplies the root the whole thing keys on.

## What this layer is not

- **Not strong secret-keeping on a shared-UID OS.** The handle *is* a shared secret and we protect it as far as the platform allows (seed-not-string, device-encrypted, session-RAM), but a same-user process on desktop defeats any file scheme — real confidentiality is the session posture or hardware, not a derivation trick. See [Confidentiality of the handle](#confidentiality-of-the-handle--and-what-desktop-cannot-promise).
- **Not the handle namespace.** Who owns "alice", uniqueness across users, registration — that's TOKEN. tohu only answers "what is *this device's* handle" and broadcasts it locally.
- **Not a change to frozen `v0`.** New `std` surface only. The derivation snapshot test is untouched; every existing vault stays exactly where it is.
