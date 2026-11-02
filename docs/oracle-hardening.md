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
| `ANDROID_ID` (the root until v139) | Resets on factory reset. Kept selectable under the ANDROID ROOT CONVERSION PIN (delete at v168) for vaults founded under it. |
| Build serial, IMEI | Need `READ_PRIVILEGED_PHONE_STATE` since Android 10. Unavailable to apps. |
| Keystore / KeyMint key attestation | Every key is generated and then stored (keystore database), and verification chains to Google's roots. Fails rule 1, and was already rejected as a Google dependency. |

Android has nothing like the TPM's deterministic primaries: KeyMint never derives a key without storing it. Widevine is as hard as an Android app can bind without storage.

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

1. **Android: DONE 2026-11-02, plate and key apart** (Nick: the car keeps its plate, the key stays in the owner's pocket). `device::machine_fingerprint()`, the key root, is the Widevine ID ‖ the APK signing certificate ‖ `ANDROID_ID`; `device::android_plate()` is `BLAKE3(Widevine ID ‖ certificate)` and survives a wipe. NEXT: publish the plate in the device's fleet and phonebook records, and a plate-refusal path so a wiped stolen phone that comes back under a new key is recognised and refused. The app selects the root once at start by which device vault is on disk (`kete::device_vault_present`): a vault under the Widevine root, or none at all, selects Widevine; only a vault under the old `ANDROID_ID` root keeps the legacy root and logs that a conversion is owed. The conversion (photon `root_conversion.rs`) runs once the legacy session is live: the old device key sponsors the new key into the fleet, the vault is re-homed entry by entry at the same addresses under the new secret (`kete::FlatStorage::rehome_into`, no domain knowledge: addresses never mix the secret in, only value keys do), the new key countersigns the old key's departure, the old vault's files go, and the process exits so the next start runs on the Widevine root. The pin that keeps the legacy root selectable is deleted at v168.
2. **Linux: plate BUILT 2026-11-02** (`device::tpm_plate()`, raw TPM 2.0 commands over `/dev/tpmrm0`, no C library): CreatePrimary under the endorsement hierarchy with the TCG EK Credential Profile's RSA-2048 template, the same template `tpm2_createek -G rsa` sends, so `b3sum` of its `-u` output equals the plate; the public half is hashed and the transient object flushed. Photon logs it at startup beside the machine-id root; nothing derives from it yet. Access: the device is `root:tss` 0660 on Fedora, Debian and Ubuntu, so the plate is absent until the user joins `tss` once (`sudo usermod -aG tss <user>`); absent means the machine keeps its `machine-id` posture. Windows follows thru TBS, where a standard user needs no elevation. That alone ends reinstall and `machine-id` sybils for unmodified clients.
3. **Then the answered form:** the deterministic HMAC primary with AK certification. That is PIPE behind the existing `tohu::pipe` / `attest` seam, with `HealthState.hardware` reporting true on a real TPM. This is the step that defeats modified clients and VM farms. It needs the verifier side (FGTW or the fleet) to check credential activation and the EK certificate chain.
4. **macOS:** no change.

## Verification still to do

- **Linux, EK is deterministic and readable without storage:** run as root, or as a user in `tss`:
  - `tpm2_createek -c - -G rsa -u ek1.pub`
  - `tpm2_createek -c - -G rsa -u ek2.pub`
  - `cmp ek1.pub ek2.pub` (identical, nothing persisted, since `-c -` means no persistent handle)
  - `tpm2_getekcertificate -u ek1.pub -o ek.crt` (for the AMD fTPM, this fetches from AMD)
  - `b3sum ek1.pub` must equal the plate photon logs at startup (`device plate: tpm <prefix>`): the same template, the same marshalled public, so the same hash
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
