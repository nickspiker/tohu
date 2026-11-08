# Hardening the device oracle

Scope, 2026-11-02. This explores what each platform offers that binds the device identity to hardware harder than today's oracle, and records why each source can or cannot be used. Nothing here is built yet.

## The rules a source must pass

1. **Nothing stored.** The identity is read or computed fresh from the device every time. A key generated once and kept in a file, a keychain, a keystore or a TPM's persistent storage fails this rule, however well protected. A stored secret is an exfiltration surface and a thing a thief can copy or reset.
2. **One device, one plate.** The value is stable across reinstalls, OS resets and app data wipes. This is the anti-sybil core: a device must not be able to mint fresh identities, and a stolen device must keep answering as itself so it can be recognised, refused and tracked. The value is never salted per handle, randomised per install or rotated per attest.
3. **Hard to fake.** Ideally the hardware itself answers a challenge, so a modified client or a virtual machine cannot claim another device's identity.

Rule 3 has two levels, and the difference matters for every source below:

- **Reported:** the client reads a value and states it. Any modified client can state any value, and any VM can be configured with one. This stops casual sybils (an honest client run on one device), which is today's threat model.
- **Answered:** the hardware computes a response to a challenge with a secret that never leaves it, and the verifier can check that real silicon produced it. This stops a modified client and a VM farm. It is what PIPE does, and the only kind of source that does.

## Today's oracle

`device_secret = BLAKE3(machine_fingerprint())`, frozen as `v0`.

| Platform | Source | Survives | Weakness |
|---|---|---|---|
| Linux | `/etc/machine-id` | reboots | Per install: an OS reinstall, or deleting the file and running `systemd-machine-id-setup`, mints a new identity. Every VM is a free new device. |
| Windows | `MachineGuid` (registry) | reboots | Per install, writable by an administrator. Every VM is a free new device. |
| macOS | `IOPlatformUUID` | OS reinstall | Bound to the logic board, so already the hardest of the four. A VM under Apple's Virtualization framework is given whatever value its host chooses. |
| Android | `ANDROID_ID` | app reinstall | A factory reset mints a new one, which hands a thief a clean plate. 64 bits. |

All four are *reported* values.

## Candidates

### TPM 2.0 (Linux and Windows): the strong one

Almost every PC since 2016 has a TPM 2.0, either a discrete chip (Infineon, STMicro, Nuvoton) or firmware in the CPU (AMD fTPM, Intel PTT). This box has an AMD fTPM (Ryzen 9 5950X, ACPI `MSFT0101`).

The TPM holds an **endorsement primary seed (EPS)** set at manufacture. Keys created with `TPM2_CreatePrimary` under the endorsement hierarchy are *derived* from the EPS and a template, so the same template gives the same key every time. A primary can be created, used and flushed with nothing written anywhere. That passes rule 1.

The EPS survives an OS reinstall and a TPM clear (`TPM2_Clear` resets the storage seed, not the endorsement seed). Only `TPM2_ChangeEPS`, which is reserved to platform firmware, or an fTPM reset changes it. That passes rule 2, with the fTPM caveat under "Gaps".

Two uses, from weakest to strongest:

1. **The EK as a plate (reported).** Create the standard endorsement key (EK) primary and hash its public part into the plate. It is unique per chip and needs no storage. On its own it is still a reported value: a modified client can claim another machine's EK public key.
2. **The TPM as PIPE (answered).** Create a keyed-hash (HMAC) primary under the endorsement hierarchy from a fixed template. It is deterministic, derived from the EPS, and never leaves the TPM. Then `TPM2_HMAC(challenge)` returns a device-bound answer computed inside the TPM. That is PIPE's `attest(challenge)` shape, with the secret in silicon.

To make the second use provable to a verifier (rule 3, "answered"), the TPM also certifies that the HMAC key lives in it:
- an attestation key (AK), also a deterministic primary;
- credential activation, which binds the AK to the EK;
- `TPM2_Certify` over the HMAC key.

The EK certificate chains to the TPM vendor's root. A VM's virtual TPM (swtpm, Hyper-V vTPM) either has no such certificate or one signed by its own CA, so a verifier can tell real silicon from a VM farm.

### Other Linux sources

| Source | Readable unprivileged | Verdict |
|---|---|---|
| SMBIOS `product_uuid`, `product_serial`, `board_serial` | No (root-only, mode 0400) | Unusable without root. Reported only, and freely settable in a VM. |
| NVMe serial (`/sys/class/nvme/nvme0/serial`) | Yes | Burned in by the drive vendor and survives reinstalls. But it moves with the drive, can be set to anything in a VM, and is reported only. At most an extra signal, never the root. |
| MAC address | Yes | Changeable in software. No. |
| CPU serial | None since the Pentium III | No. |
| Widevine | Desktop Linux has only Widevine L3, a software CDM inside the browser with no hardware root, and it cannot be reached outside the browser. | No. |

### Other Windows sources

| Source | Verdict |
|---|---|
| SMBIOS UUID via `GetSystemFirmwareTable('RSMB')` | Readable by a standard user. Reported only, and settable in a VM. At most an extra signal. |
| PlayReady hardware DRM (SL3000) | Exists on some GPUs, tied to Microsoft licensing, and has no device-ID interface open to an ordinary app. No. |
| TPM | See above. Windows reaches it through TBS (`Tbsip_Submit_Command`), which takes raw TPM commands with no stored key. Not the Platform Crypto Provider, whose keys are persisted, which breaks rule 1. |

### macOS

| Source | Verdict |
|---|---|
| `IOPlatformUUID` (current) | Keep. Board-bound, survives reinstalls. |
| Secure Enclave | Every Secure Enclave key is generated and then stored (keychain). It has no deterministic, derived key. Fails rule 1. |
| App Attest / DeviceCheck | App Attest is iOS-only. DeviceCheck stores state on Apple's servers. Both make Apple a party. No. |

So macOS stays as it is. It is the strongest of today's oracles, and Apple offers no answered source without storage or Apple's servers.

### Android

| Source | Verdict |
|---|---|
| Widevine `MediaDrm` `PROPERTY_DEVICE_UNIQUE_ID` | **Verified 2026-11-02 on a Pixel 8 Pro.** Read with no permission, rooted in the device's Widevine credential (L1, TEE-backed on Pixel), no Google server involved in reading it: the read works in airplane mode. 32 bytes, and byte-identical across a factory reset, which `ANDROID_ID` is not. Readable by every app on the phone (not scoped per signer), so it is the PLATE, `BLAKE3(id ‖ signing certificate)`, and the KEY root folds `ANDROID_ID` in as well: `id ‖ certificate ‖ ANDROID_ID`, secret from other apps and rotated by a wipe. A reported value as read by the app. |
| `ANDROID_ID` (the root until v139) | Resets on factory reset. Kept selectable under the ANDROID ROOT CONVERSION PIN (MIGRATION-EXPIRES: 2027-02-01) for vaults founded under it. |
| Build serial, IMEI | Need `READ_PRIVILEGED_PHONE_STATE` since Android 10. Unavailable to apps. |
| Keystore / KeyMint key attestation | Every key is generated and then stored (keystore database), and verification chains to Google's roots. Fails rule 1, and was already rejected as a Google dependency. |

Android has nothing like the TPM's deterministic primaries: KeyMint never derives a key without storing it. Widevine is as hard as an Android app can bind without storage.

## Assurance levels

Beside its plate a device states what the plate names (`fgtw::fleet::plate`), and a reader derives a level from it, by what an attacker needs to become the device:

| level | kind | root | to clone the device |
|---|---|---|---|
| 0 | file | `machine-id`, `MachineGuid` | any local code, or a disk image |
| 1 | firmware | `IOPlatformUUID` | any local code |
| 2 | scoped | Widevine ‖ certificate ‖ `ANDROID_ID` | root, or the app's signing key |
| 3 | silicon key | TPM HMAC primary | the box itself |
| 4 | answered | PIPE, or a TPM with certification | the chip itself, and a verifier can tell |

Levels 0 to 3 are the device's own statement; a modified client can state any of them. Only the answered form, a proof carried beside a PIPE plate, makes level 4 more than a statement, and nothing a stated level unlocks may exceed what a proven one would. Photon shows each device's level on the Fleet page as stated (2026-11-02); a fleet-key floor by level and a threshold proof shown to friends are later work.

## Gaps

1. **TPM access on Linux.** `/dev/tpmrm0` is `root:tss` mode 0660 (Fedora's `60-tpm-udev.rules`), and a normal user is not in `tss`. The installer would have to add the user to `tss` once (`usermod -aG tss`, needs root once), or ship a udev rule granting the active seat. Without it the app cannot reach the TPM and falls back to `machine-id`.
2. **fTPM resets.** An AMD fTPM can lose its seed on a CPU swap, and some boards offer to reset it after a firmware update ("fTPM NV corrupted or structure changed"). Intel PTT has similar firmware-update edge cases. A reset is a new plate, the same as a factory reset on a phone: the fleet sees a new device. A discrete TPM does not have this.
3. **fTPM EK certificates are online.** Discrete TPMs carry their EK certificate in NV storage. AMD and Intel firmware TPMs do not: the certificate is fetched from the vendor (`ftpm.amd.com`, `ekop.intel.com`) by the hash of the EK public key. Only the verifier needs it, once per device, so it could be FGTW's job. But it is a dependency on AMD's and Intel's servers for the "real silicon" proof.
4. **Endorsement-hierarchy authorisation on Windows.** Creating primaries under the endorsement hierarchy needs its authorisation value, which is normally empty. Whether Windows keeps it empty on current builds, and whether TBS lets a standard user submit `CreatePrimary` / `HMAC` (Windows can block TPM commands by policy), must be tested on a Windows machine.
5. **Widevine scoping: tested 2026-11-02, not scoped.** A build re-signed with a throwaway key read the same raw ID on the Pixel 8 Pro while `ANDROID_ID` changed with the signer. So every app on the phone can read the ID, and the app family's root (`ID ‖ signing certificate`) is computable by any app from public inputs. That is the desktop posture (`machine-id` is world-readable), a step down from `ANDROID_ID`'s per-signer scoping, accepted as the price of a root that survives a wipe; the Security posture stays at one pip until PIPE.
6. **No TPM.** Older PCs and most VMs have none. They keep `machine-id` / `MachineGuid` with the low Security posture, exactly as today.
7. **The frozen `v0`.** Changing what feeds `device_secret` changes every key derived from it and strands every vault. So a new source either:
   - goes in as a separate **plate** beside the unchanged `device_secret` (published to the fleet and FGTW, checked for consistency, no migration); or
   - becomes a versioned `v1` oracle with a planned migration.

   Decided for Android 2026-11-02: the source is swapped under the unchanged v0 derivation, the old source stays selectable under a conversion pin for thirty versions (until v168), and a vault founded under the old root keeps it until converted. Desktop keeps `machine-id`, `MachineGuid` and `IOPlatformUUID`; the TPM work below would follow the same shape.

## Recommended direction

1. **Android: DONE 2026-11-02, plate and key apart** (Nick: the car keeps its plate, the key stays in the owner's pocket). `device::machine_fingerprint()`, the key root, is the Widevine ID ‖ the APK signing certificate ‖ `ANDROID_ID`; `device::android_plate()` is `BLAKE3(Widevine ID ‖ certificate)` and survives a wipe. PLATE PUBLICATION BUILT 2026-11-02 (fgtw `FleetOp::plate`, op version v3): a device's plate rides its own signed genesis and declare ops and its binding request, so the sponsor's add carries it as the joiner's word; the fold exposes `declared_plate`, `plates` and `locked_plates`. Refusal in three places: the seed holds a plate→owner index beside the device→owner one, so a plate another fleet still lists (a lock keeps it listed for good) can neither found a new identity nor post a request to join one (`plate_owned`); a sponsor refuses a joiner whose plate its own fleet locked out; a device release frees the plate with the key, so a sold device can hold a new identity. The app selects the root once at start by which device vault is on disk (`kete::device_vault_present`): a vault under the Widevine root, or none at all, selects Widevine; only a vault under the old `ANDROID_ID` root keeps the legacy root and logs that a conversion is owed. The conversion (photon `root_conversion.rs`) runs once the legacy session is live: the old device key sponsors the new key into the fleet, the vault is re-homed entry by entry at the same addresses under the new secret (`kete::FlatStorage::rehome_into`, no domain knowledge: addresses never mix the secret in, only value keys do), the new key countersigns the old key's departure, the old vault's files go, and the process exits so the next start runs on the Widevine root. The pin that keeps the legacy root selectable is deleted at v168.
2. **Linux: plate BUILT 2026-11-02** (`device::tpm_plate()`, raw TPM 2.0 commands over `/dev/tpmrm0`, no C library): CreatePrimary under the endorsement hierarchy with the TCG EK Credential Profile's RSA-2048 template, the same template `tpm2_createek -G rsa` sends, so `b3sum` of its `-u` output equals the plate; the public half is hashed and the transient object flushed. Photon logs it at startup beside the machine-id root; nothing derives from it yet. Access: the device is `root:tss` 0660 on Fedora, Debian and Ubuntu, so the plate is absent until the user joins `tss` once (`sudo usermod -aG tss <user>`); absent means the machine keeps its `machine-id` posture. Windows follows thru TBS, where a standard user needs no elevation. That alone ends reinstall and `machine-id` sybils for unmodified clients.
3. **Linux key half: BUILT + VERIFIED 2026-11-02.** `device::tpm_hmac(message)` creates a keyed-hash (HMAC-SHA256) primary under the endorsement hierarchy from a fixed template (attributes fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | noDA | sign, our own policy digest as the template's identity), asks the chip for `TPM2_HMAC(message)`, and flushes it; `device::tpm_root()` is the HMAC over the label `tohu.device-root.v0`, one value per chip for this application. On the AMD fTPM the root came back identical across calls and a different message gave a different tag, with no transient or persistent object left behind. The secret never leaves the chip, so nothing can be copied off the machine; a local process can still ask the chip to answer, which is the same posture as Android's key. Photon logs the prefix beside the plate; nothing derives from it yet. Making it the root is a source swap under the unchanged v0 derivation with a thirty-version conversion pin, the way Android moved.
4. **Then the answered form:** the same HMAC primary with AK certification. That is PIPE behind the existing `tohu::pipe` / `attest` seam, with `HealthState.hardware` reporting true on a real TPM. This is the step that defeats modified clients and VM farms. It needs the verifier side (FGTW or the fleet) to check credential activation and the EK certificate chain.
5. **macOS:** no change.

## Beyond the oracle: a tag in the pocket, or the kernel

Direction from the owner, 2026-11-08; nothing of it built.

**The problem.** A plate source answers anyone who asks.
On Android any app reads the Widevine ID (gap 5); the key root also mixes in `ANDROID_ID`, which is per signer, so another developer's app cannot compute ours, but root or an app signed with our key can.
On the desktop any process of the same user reads `machine-id`, `MachineGuid` or `IOPlatformUUID`, can ask the TPM HMAC primary for the same answer (anyone in `tss`), and can read the session registers.
The plate may be public, since it only names the device. The trust has to come from something only the owner holds.

**The owner's direction:** keep binding the plate, and add a crypto tag as the trust half, PIPE carried in a pocket, domain-separated by handle; or have the kernel enforce a software PIPE.
Both are unconventional; both are to be built and kept on record here.

### A tag as PIPE

PIPE's interface is 256 bits in, 256 bits out, the same answer to the same question, and a secret that never leaves the chip.

- **A FIDO2 authenticator with `hmac-secret` (CTAP 2.1) fits exactly.** A 32-byte salt goes in and HMAC-SHA-256 under a per-credential secret comes out; the secret is made in the chip and never exported, the answer repeats for the same credential and salt, and the tap is the presence.
  - One key speaks NFC to a phone and USB to a desktop. Keys are off the shelf, from many vendors, and no vendor is in the loop when one answers.
  - Domain separation by handle: the salt is a keyed BLAKE3 of `handle_proof` under a context string, so the tag never sees the identity itself and each handle gets its own answer from one credential.
  - A discoverable credential lets the client keep nothing at all; a non-discoverable one keeps only the credential id, which the tag wrapped and which is useless without it.
  - The answered form: the credential's attestation certificate at creation is the vendor's, a DMV-issued value checked offline.
- **NTAG 424 DNA is the wrong shape**, though it resists cloning.
  - Its AES keys are symmetric, so whoever checks the tag must hold its key too, and that key would sit on our devices, the exfiltration surface rule 1 exists to avoid.
  - Its SUN MAC is bound to a counter that advances on every read, so the answer never repeats and nothing can be derived from it.
  - It proves a tag is genuine to a server that holds its key; it cannot stand in for PIPE.
- **A JavaCard NFC card** (an applet holding a key generated on the card) also fits and allows an applet of our own, at the cost of writing and loading one.

How it fits the rules above:

- **The plate stays the device's** (rule 2): one device, one plate, published, never salted.
- **The tag is the person's, so it joins the key half,** which on Android already sits apart from the plate. The device's trust then needs both what the device is and what its owner carries.
- **Rule 7 holds.** `device_secret` is frozen at `v0`, so the tag does not feed it. It gates a layer above: the fleet signing key, or the vault's unlock, needs the tag's answer. The derivation and every vault stay as they are. A versioned `v1` oracle is the other path.
- **One tap per boot,** at attest and at Locked → Live, matching "signed in until power-off". The session registers are what remains exposed while a session is live.
- **A lost tag is recovered like a lost device:** a sibling sponsors a fresh bind with a new tag, and an identity can enroll a spare tag ahead of time.
- **The assurance table needs a row** for a device whose key half is tag-gated.

### Papers in the glovebox

The owner, 2026-11-08: "leave the plate on each one, the best we can, then put the cert in the glovebox."
The plate stays the device's public name; the **papers** are a key made inside the device's secure hardware and never exportable (StrongBox, the TPM, the Secure Enclave), registered in the fleet.
A factory reset destroys the papers and leaves the plate claimed by its owner, so only the owner's tap brings the device back, and green on the device in hand becomes proof (photon docs/one-identity.md, "Plate and papers").
This would overturn rule 1 for the key half: a non-exportable key is stored, but it cannot be copied, which is what the rule guards, and using it locally puts no vendor in the loop. That is the owner's ruling to make; the open points (the frozen `v0`, uninstall on Android, desktop papers that die on reinstall) are listed there.

### Kernel enforcement: a software PIPE

The OS refuses every process but ours access to the root:

- **Linux: feasible.** First without a patch: an SELinux or AppArmor profile that lets only our signed binary open `/dev/tpmrm0` and the session directory, with Yama `ptrace_scope` at 1 or more. A small module or LSM is the stronger form. It needs root once, as the `tss` membership does (gap 1).
- **Android: only on a kernel we flash.** No ordinary phone can take it; ferros already enforces this natively.
- **Windows: heavy.** A kernel driver needs Microsoft's attestation signing, and an administrator can still remove it.
- **macOS: not viable.** Third-party kernel extensions are deprecated.

So the kernel route covers Linux (and ferros), and the tag route covers every phone with NFC and every desktop with USB.
**Recommended: the tag first.**

## Verification still to do

- **Linux, EK is deterministic and readable without storage: VERIFIED 2026-11-02** on an AMD fTPM (Ryzen 9 5950X) as a user in `tss`. Two `tpm2_createek -G rsa -u` runs gave identical files, and `b3sum` of that file equalled `tohu::device::tpm_plate()` run against the same chip, byte for byte: the template, the marshalling and the parse all agree with the reference tool. Caution: `tpm2_createek -c -` PERSISTS the key (it printed `persistent-handle: 0x81000000` and `0x81000003`, evicted afterwards with `tpm2_evictcontrol -C o -c <handle>`); use `-c ek.ctx` for a transient context instead. tohu's own path persists nothing (CreatePrimary then FlushContext).
  - `tpm2_getekcertificate -u ek1.pub -o ek.crt` (for the AMD fTPM, this fetches from AMD): not yet run, only the answered form needs it.
- **Linux, HMAC primary is deterministic:**
  - `tpm2_createprimary -C e -G hmac -c hm.ctx`
  - `echo -n probe | tpm2_hmac -c hm.ctx`
  - Run both commands twice; the output must match. Then `tpm2_flushcontext -t`.
- **Linux, TPM survives an OS reinstall:** compare the EK hash before and after a reinstall (or a live USB on the same machine).
- **Windows:** the same `CreatePrimary` / `HMAC` sequence through TBS as a standard user, and whether `Get-TpmEndorsementKeyInfo` needs elevation.
- **Android, Widevine:** BUILT 2026-11-02 as `device::widevine_id()` plus `device::signing_cert()`, called by photon's `widevine_probe()` at service start. It logs `widevine probe: id <blake3 prefix> (<n> bytes), level L1|L3, cdm <version>, plate(id ‖ signing cert) <blake3 prefix>`, or `unreadable (<exception>)`. Run it in airplane mode: a value there proves the read needs no network. First result, Pixel 8 Pro in airplane mode, 2026-11-02: 32-byte ID, level L1, CDM 19.5.0, so the read is local. Compare the prefixes:
  - across an app reinstall;
  - across two apps signed with our key;
  - across a factory reset of a spare device (not the daily Pixel unless the owner chooses to).
- **FIDO2 `hmac-secret`, per platform:**
  - Android: CTAP 2 over NFC as plain ISO-DEP APDUs from the app (no Google FIDO API in the loop).
  - Linux: `hidraw` access to the key needs a udev rule (libfido2 ships one).
  - macOS: USB HID from an unsandboxed app.
  - Windows: non-administrator apps reach FIDO keys only through Windows' WebAuthn API; whether it passes `hmac-secret` through to us needs checking.
  - Everywhere: the same salt twice gives the same 32 bytes, and two handles' salts give unrelated answers.
