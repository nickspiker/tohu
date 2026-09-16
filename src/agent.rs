//! The handle-slot wire — framed VSF, one protocol, every transport.
//!
//! `docs/handle.md` fixes four messages (`Get` / `Set` / `Clear` / `Health`) and says they
//! ride a UID-authenticated unix socket on desktop and a signing-key-gated bound service on
//! Android, because Android sandboxes apps to *different* UIDs and a same-UID socket cannot
//! reach across them. Both carry these identical bytes: one codec to audit, one format to
//! keep compatible, and the desktop agent and the Android broker can never drift apart.
//!
//! **No outer framing is needed.** A VSF file carries its own total length (`l`, "exactly one
//! per file", the type that exists so TCP readers can preallocate), so the document IS the
//! frame on a stream transport, and Binder hands over a sized byte array anyway.
//!
//! The wire is a complete VSF file with a provenance hash, per the stack's transport rule:
//! raw types on a wire have no integrity and no version, so every message is a whole document
//! that `vsfinfo` can inspect and anything can verify.
//!
//! Nothing here touches the frozen `v0` derivation primitives — this layer only moves an
//! already-derived seed between processes.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use vsf::file_format::{VsfHeader, VsfSection};
use vsf::types::VsfType;
use vsf::vsf_builder::VsfBuilder;

/// Section name on a request document.
const SEC_REQ: &str = "req";
/// Section name on a response document.
const SEC_RSP: &str = "rsp";
/// The discriminant field both sections carry.
const F_OP: &str = "op";
/// base64url slot address (43 chars, no padding) — see [`crate::handle_slot_id`].
const F_SLOT: &str = "slot";
/// The 32-byte handle seed, typed `hV` (VSF's "vault seed: BLAKE3-derived local storage root").
const F_SEED: &str = "seed";
/// Health's readiness bit.
const F_READY: &str = "ready";

/// A request to the holder of the handle slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Read the slot.
    Get { slot: String },
    /// First-run write. **First-write-wins, never clobbers** — the race-safe rule from
    /// `handle.md`, and the reason two apps launching together cannot produce two handles.
    Set { slot: String, seed: [u8; 32] },
    /// Forget the slot (logout / drop).
    Clear { slot: String },
    /// "Is the store up?" — mirrors [`crate::pipe`]'s health challenge. Touches no secret and
    /// names no slot, so it is safe to answer before any gate decision.
    Health,
}

/// The holder's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    /// The slot held this seed.
    Seed([u8; 32]),
    /// The slot is empty — first run, or after a `Clear`.
    NotSet,
    /// `Set` stored the seed, or `Clear` removed it.
    Ok,
    /// `Set` refused: the slot already holds a seed. Not an error — it is the first-write-wins
    /// rule firing, and the caller should `Get` and use what is already there.
    AlreadySet,
    /// The RAM store is up.
    Health { ready: bool },
    /// The caller did not pass the transport's gate.
    ///
    /// **Not in `handle.md`'s four messages** — added because the Android transport gates on the
    /// caller's signing-key lineage and a refusal needs a name on the wire. The desktop agent,
    /// whose gate is the UID the socket already enforces, never mints this.
    Denied,
}

impl Request {
    fn op(&self) -> &'static str {
        match self {
            Request::Get { .. } => "get",
            Request::Set { .. } => "set",
            Request::Clear { .. } => "clear",
            Request::Health => "health",
        }
    }

    /// Encode to a complete, provenance-hashed VSF document.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut fields: Vec<(String, VsfType)> =
            vec![(F_OP.to_string(), VsfType::a(self.op().to_string()))];
        match self {
            Request::Get { slot } | Request::Clear { slot } => {
                fields.push((F_SLOT.to_string(), VsfType::a(slot.clone())));
            }
            Request::Set { slot, seed } => {
                fields.push((F_SLOT.to_string(), VsfType::a(slot.clone())));
                fields.push((F_SEED.to_string(), VsfType::hV(seed.to_vec())));
            }
            Request::Health => {}
        }
        VsfBuilder::new()
            .provenance_only()
            .add_section(SEC_REQ, fields)
            .build()
    }

    /// Decode a request document. `Err` on a bad checksum, a missing section, an unknown op, or
    /// a field of the wrong type — every one of which is a malformed peer, not a usable message.
    pub fn decode(bytes: &[u8]) -> Result<Request, String> {
        let section = section_of(bytes, SEC_REQ)?;
        let op = ascii_field(&section, F_OP)?;
        match op.as_str() {
            "get" => Ok(Request::Get {
                slot: ascii_field(&section, F_SLOT)?,
            }),
            "clear" => Ok(Request::Clear {
                slot: ascii_field(&section, F_SLOT)?,
            }),
            "set" => Ok(Request::Set {
                slot: ascii_field(&section, F_SLOT)?,
                seed: seed_field(&section, F_SEED)?,
            }),
            "health" => Ok(Request::Health),
            other => Err(format!("unknown request op: {other}")),
        }
    }
}

impl Response {
    fn op(&self) -> &'static str {
        match self {
            Response::Seed(_) => "seed",
            Response::NotSet => "notset",
            Response::Ok => "ok",
            Response::AlreadySet => "alreadyset",
            Response::Health { .. } => "health",
            Response::Denied => "denied",
        }
    }

    /// Encode to a complete, provenance-hashed VSF document.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut fields: Vec<(String, VsfType)> =
            vec![(F_OP.to_string(), VsfType::a(self.op().to_string()))];
        match self {
            Response::Seed(seed) => {
                fields.push((F_SEED.to_string(), VsfType::hV(seed.to_vec())));
            }
            Response::Health { ready } => {
                fields.push((F_READY.to_string(), VsfType::u0(*ready)));
            }
            Response::NotSet | Response::Ok | Response::AlreadySet | Response::Denied => {}
        }
        VsfBuilder::new()
            .provenance_only()
            .add_section(SEC_RSP, fields)
            .build()
    }

    /// Decode a response document.
    pub fn decode(bytes: &[u8]) -> Result<Response, String> {
        let section = section_of(bytes, SEC_RSP)?;
        let op = ascii_field(&section, F_OP)?;
        match op.as_str() {
            "seed" => Ok(Response::Seed(seed_field(&section, F_SEED)?)),
            "notset" => Ok(Response::NotSet),
            "ok" => Ok(Response::Ok),
            "alreadyset" => Ok(Response::AlreadySet),
            "denied" => Ok(Response::Denied),
            "health" => Ok(Response::Health {
                ready: match section.get_field(F_READY).and_then(|f| f.values.first()) {
                    Some(VsfType::u0(v)) => *v,
                    _ => return Err(format!("{F_READY}: missing or not a bool")),
                },
            }),
            other => Err(format!("unknown response op: {other}")),
        }
    }
}

/// Decode the document and pull out the one section we expect.
/// `VsfHeader::decode` validates the provenance checksum, so a scribbled or truncated message
/// dies here rather than downstream as a confusing field error.
fn section_of(bytes: &[u8], name: &str) -> Result<VsfSection, String> {
    let (header, _) = VsfHeader::decode(bytes).map_err(|e| format!("bad VSF document: {e:?}"))?;
    let field = header
        .fields
        .iter()
        .find(|f| f.name == name)
        .ok_or_else(|| format!("no `{name}` section"))?;
    let mut ptr = field.offset_bytes;
    VsfSection::parse(bytes, &mut ptr).map_err(|e| format!("bad `{name}` section: {e:?}"))
}

fn ascii_field(section: &VsfSection, name: &str) -> Result<String, String> {
    match section.get_field(name).and_then(|f| f.values.first()) {
        Some(VsfType::a(s)) => Ok(s.clone()),
        _ => Err(format!("{name}: missing or not ASCII text")),
    }
}

/// A seed field must be `hV` and exactly 32 bytes. The length check is not decoration: a short
/// seed silently truncated into a `[u8; 32]` would derive a different vault, so it fails loudly.
fn seed_field(section: &VsfSection, name: &str) -> Result<[u8; 32], String> {
    match section.get_field(name).and_then(|f| f.values.first()) {
        Some(VsfType::hV(v)) => {
            let arr: [u8; 32] = v
                .as_slice()
                .try_into()
                .map_err(|_| format!("{name}: expected 32 bytes, got {}", v.len()))?;
            Ok(arr)
        }
        _ => Err(format!("{name}: missing or not a vault seed (hV)")),
    }
}

/// The transport's verdict on whether a caller may touch the slot.
///
/// Each transport authenticates differently and this is the seam between them: the desktop socket
/// is `0600` and peer-authenticated by UID, so the OS has already decided by the time bytes
/// arrive; Android has no such luxury (apps run under *different* UIDs) and must check the
/// caller's signing-certificate lineage against `Binder.getCallingUid()`. Same store, same codec,
/// different gate.
///
/// Keep the Android implementation in one function so ferros can later replace its body with a
/// kernel code measurement without touching this trait, the codec, or any caller.
pub trait Gate {
    /// `true` to serve, `false` to answer [`Response::Denied`].
    fn admit(&self, req: &Request) -> bool;
}

/// Admits everything — correct wherever the transport itself is the gate.
///
/// Not a test stub: on the desktop socket the `0600` mode plus UID peer-authentication *is* the
/// boundary, and re-checking inside would be theatre. Wrong for Android, which is exactly why
/// `admit` is a trait rather than a flag.
pub struct TransportIsTheGate;

impl Gate for TransportIsTheGate {
    fn admit(&self, _req: &Request) -> bool {
        true
    }
}

/// Decode → gate → serve → encode: the whole request path, shared by every transport.
///
/// `Health` is answered without consulting the gate. It touches no secret, names no slot, and
/// reveals only what kind of store is answering — so a caller that will be refused everything
/// else can still discover the broker is alive, which is what lets a client pick the degraded
/// path instead of hanging.
///
/// `Err` means the bytes were not a request at all (bad checksum, truncation, unknown op). That
/// is a transport-level fault, not a protocol answer, so it is returned as an error for the
/// transport to signal in its own idiom rather than fabricating a response the spec has no room
/// for.
pub fn serve_bytes<G: Gate>(
    store: &SlotStore,
    gate: &G,
    bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let req = Request::decode(bytes)?;
    let rsp = match req {
        Request::Health => Response::Health { ready: true },
        _ if !gate.admit(&req) => Response::Denied,
        _ => store.serve(&req),
    };
    rsp.encode()
}

/// A 32-byte handle seed that scrubs itself.
///
/// Deliberately **not** `Copy` and not `Clone`. [`crate::SessionIdentity`] is `Copy`, which makes
/// zeroization structurally impossible for its callers — every pass by value leaves a copy behind
/// that nobody owns and nobody can wipe. This type is the other choice: it moves, so there is
/// exactly one live copy and exactly one `Drop` that clears it.
pub struct HandleSeed([u8; 32]);

impl HandleSeed {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Redacted — a seed must never reach a log line by way of a derived `Debug`.
impl core::fmt::Debug for HandleSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HandleSeed(<redacted>)")
    }
}

impl Drop for HandleSeed {
    fn drop(&mut self) {
        scrub(&mut self.0);
    }
}

/// Volatile write + fence. A plain `= 0` loop on a value that is never read again is a dead store
/// and LLVM may delete it outright — which is how "we zeroed it" becomes a comment rather than a
/// fact. This is the same discipline `zeroize` implements; tohu has no such dependency and this is
/// the whole of what it needs.
fn scrub(bytes: &mut [u8; 32]) {
    for b in bytes.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// The RAM-held handle slot — what the desktop agent and the Android broker both wrap.
///
/// One slot per device, per `docs/handle.md`'s rule ("one handle per device — not per app"). The
/// store enforces that rule locally; it is **not** a security boundary (a determined local user
/// writes whatever bytes they like, and real sybil resistance lives on the network) — it buys
/// coherence, so every honest app on the device reads the same handle.
///
/// Transport-free on purpose: every gate decision happens above this, so the store can be tested
/// exhaustively without a socket, a Binder, or a device fact.
pub struct SlotStore {
    inner: std::sync::Mutex<Option<(String, [u8; 32])>>,
}

impl Default for SlotStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SlotStore {
    pub const fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(None),
        }
    }

    /// Answer one request.
    ///
    /// `Set` is **first-write-wins and never clobbers**. That is the race-safe rule from
    /// `handle.md` and it is the entire reason two apps launching at once cannot mint two handles:
    /// the loser is told `AlreadySet` and re-`Get`s the winner's seed. A last-write-wins store
    /// would let a late starter silently replace the device's identity root.
    ///
    /// A `Set` naming a *different* slot is refused for the same reason — one slot per device is
    /// the invariant, and a mismatched address means the caller derived a different
    /// `device_secret` (on Android, a different signing cert), which phase 1 does not unify.
    pub fn serve(&self, req: &Request) -> Response {
        match req {
            Request::Health => Response::Health { ready: true },

            Request::Get { slot } => match &*self.inner.lock().unwrap() {
                Some((id, seed)) if id == slot => Response::Seed(*seed),
                // Occupied-but-different reads as empty, not as a denial: a wrong address learns
                // nothing about whether some other address is filled.
                _ => Response::NotSet,
            },

            Request::Set { slot, seed } => {
                let mut guard = self.inner.lock().unwrap();
                match &*guard {
                    Some(_) => Response::AlreadySet,
                    None => {
                        *guard = Some((slot.clone(), *seed));
                        Response::Ok
                    }
                }
            }

            Request::Clear { slot } => {
                let mut guard = self.inner.lock().unwrap();
                if let Some((id, seed)) = guard.as_mut() {
                    if id == slot {
                        scrub(seed);
                        *guard = None;
                    }
                }
                // `Ok` regardless: clearing an absent slot is the desired end state, and a
                // distinct "wasn't there" answer would turn Clear into an occupancy oracle.
                Response::Ok
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLOT: &str = "Zm9vYmFyYmF6cXV1eGNvcmdlZ3JhdWx0Z2FycGx5Z2g";
    const SEED: [u8; 32] = [7u8; 32];

    fn round_trip_request(r: Request) {
        let bytes = r.encode().expect("encode");
        assert_eq!(Request::decode(&bytes).expect("decode"), r);
    }

    fn round_trip_response(r: Response) {
        let bytes = r.encode().expect("encode");
        assert_eq!(Response::decode(&bytes).expect("decode"), r);
    }

    #[test]
    fn requests_round_trip() {
        round_trip_request(Request::Get {
            slot: SLOT.to_string(),
        });
        round_trip_request(Request::Set {
            slot: SLOT.to_string(),
            seed: SEED,
        });
        round_trip_request(Request::Clear {
            slot: SLOT.to_string(),
        });
        round_trip_request(Request::Health);
    }

    #[test]
    fn responses_round_trip() {
        round_trip_response(Response::Seed(SEED));
        round_trip_response(Response::NotSet);
        round_trip_response(Response::Ok);
        round_trip_response(Response::AlreadySet);
        round_trip_response(Response::Denied);
        round_trip_response(Response::Health { ready: true });
        round_trip_response(Response::Health { ready: false });
    }

    /// A request must never decode as a response. The section name is the discriminant, so a
    /// transport that crossed its streams fails loudly instead of misreading an op.
    #[test]
    fn request_and_response_namespaces_are_disjoint() {
        let req = Request::Health.encode().unwrap();
        assert!(Response::decode(&req).is_err());
        let rsp = Response::Ok.encode().unwrap();
        assert!(Request::decode(&rsp).is_err());
    }

    /// The provenance checksum is the integrity boundary — flipping any byte must be caught.
    #[test]
    fn tampering_is_detected() {
        let mut bytes = Request::Set {
            slot: SLOT.to_string(),
            seed: SEED,
        }
        .encode()
        .unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        assert!(Request::decode(&bytes).is_err());
    }

    #[test]
    fn truncation_is_detected() {
        let bytes = Request::Health.encode().unwrap();
        assert!(Request::decode(&bytes[..bytes.len() / 2]).is_err());
        assert!(Request::decode(&[]).is_err());
    }

    /// A `Set` whose seed is not 32 bytes must fail rather than truncate into a different vault.
    #[test]
    fn short_seed_is_rejected() {
        let bytes = VsfBuilder::new()
            .provenance_only()
            .add_section(
                SEC_REQ,
                vec![
                    (F_OP.to_string(), VsfType::a("set".to_string())),
                    (F_SLOT.to_string(), VsfType::a(SLOT.to_string())),
                    (F_SEED.to_string(), VsfType::hV(vec![1u8; 16])),
                ],
            )
            .build()
            .unwrap();
        assert!(Request::decode(&bytes).is_err());
    }

    #[test]
    fn set_then_get_round_trips() {
        let store = SlotStore::new();
        assert_eq!(
            store.serve(&Request::Get {
                slot: SLOT.to_string()
            }),
            Response::NotSet
        );
        assert_eq!(
            store.serve(&Request::Set {
                slot: SLOT.to_string(),
                seed: SEED
            }),
            Response::Ok
        );
        assert_eq!(
            store.serve(&Request::Get {
                slot: SLOT.to_string()
            }),
            Response::Seed(SEED)
        );
    }

    /// The rule that makes two simultaneous launches safe: the second writer is refused and the
    /// original seed survives untouched.
    #[test]
    fn first_write_wins() {
        let store = SlotStore::new();
        assert_eq!(
            store.serve(&Request::Set {
                slot: SLOT.to_string(),
                seed: SEED
            }),
            Response::Ok
        );
        assert_eq!(
            store.serve(&Request::Set {
                slot: SLOT.to_string(),
                seed: [9u8; 32]
            }),
            Response::AlreadySet
        );
        assert_eq!(
            store.serve(&Request::Get {
                slot: SLOT.to_string()
            }),
            Response::Seed(SEED),
            "the clobber must not have landed"
        );
    }

    /// Concurrency is the risk `global-vault.md` names as "genuinely new work". Hammer one store
    /// from many threads: exactly one `Set` may win, and every reader must agree on the winner.
    #[test]
    fn concurrent_set_has_exactly_one_winner() {
        use std::sync::Arc;

        const THREADS: u8 = 16;
        for _round in 0..64 {
            let store = Arc::new(SlotStore::new());
            let start = Arc::new(std::sync::Barrier::new(THREADS as usize));
            let handles: Vec<_> = (0..THREADS)
                .map(|i| {
                    let store = Arc::clone(&store);
                    let start = Arc::clone(&start);
                    std::thread::spawn(move || {
                        start.wait();
                        store.serve(&Request::Set {
                            slot: SLOT.to_string(),
                            seed: [i; 32],
                        })
                    })
                })
                .collect();

            let wins = handles
                .into_iter()
                .map(|h| h.join().expect("thread panicked"))
                .filter(|r| *r == Response::Ok)
                .count();
            assert_eq!(wins, 1, "exactly one writer may win the slot");

            // And the survivor is one of the offered seeds, whole — never a torn mix.
            match store.serve(&Request::Get {
                slot: SLOT.to_string(),
            }) {
                Response::Seed(seed) => {
                    assert!(
                        (0..THREADS).any(|i| seed == [i; 32]),
                        "slot holds a seed nobody wrote"
                    );
                }
                other => panic!("expected a seed, got {other:?}"),
            }
        }
    }

    #[test]
    fn clear_empties_the_slot_and_is_idempotent() {
        let store = SlotStore::new();
        store.serve(&Request::Set {
            slot: SLOT.to_string(),
            seed: SEED,
        });
        assert_eq!(
            store.serve(&Request::Clear {
                slot: SLOT.to_string()
            }),
            Response::Ok
        );
        assert_eq!(
            store.serve(&Request::Get {
                slot: SLOT.to_string()
            }),
            Response::NotSet
        );
        // Clearing an absent slot is still Ok — the end state is what was asked for, and a
        // distinct answer would make Clear an occupancy oracle.
        assert_eq!(
            store.serve(&Request::Clear {
                slot: SLOT.to_string()
            }),
            Response::Ok
        );
        // ...and the slot is writable again afterwards.
        assert_eq!(
            store.serve(&Request::Set {
                slot: SLOT.to_string(),
                seed: [3u8; 32]
            }),
            Response::Ok
        );
    }

    /// A caller that derived a different `device_secret` (on Android: a different signing cert)
    /// gets `NotSet`, never someone else's seed, and cannot clobber the occupant.
    #[test]
    fn a_foreign_slot_id_reads_empty_and_cannot_clobber() {
        const OTHER: &str = "b3RoZXJzbG90aWRvdGhlcnNsb3RpZG90aGVyc2xvdGlk";
        let store = SlotStore::new();
        store.serve(&Request::Set {
            slot: SLOT.to_string(),
            seed: SEED,
        });
        assert_eq!(
            store.serve(&Request::Get {
                slot: OTHER.to_string()
            }),
            Response::NotSet
        );
        assert_eq!(
            store.serve(&Request::Set {
                slot: OTHER.to_string(),
                seed: [9u8; 32]
            }),
            Response::AlreadySet
        );
        assert_eq!(
            store.serve(&Request::Clear {
                slot: OTHER.to_string()
            }),
            Response::Ok
        );
        assert_eq!(
            store.serve(&Request::Get {
                slot: SLOT.to_string()
            }),
            Response::Seed(SEED),
            "a foreign Clear must not evict the occupant"
        );
    }

    #[test]
    fn health_needs_no_slot_and_answers_ready() {
        let store = SlotStore::new();
        assert_eq!(
            store.serve(&Request::Health),
            Response::Health { ready: true }
        );
    }

    #[test]
    fn handle_seed_does_not_leak_thru_debug() {
        let seed = HandleSeed::new([0xAB; 32]);
        assert_eq!(format!("{seed:?}"), "HandleSeed(<redacted>)");
        assert_eq!(seed.as_bytes(), &[0xAB; 32]);
    }

    struct DenyAll;
    impl Gate for DenyAll {
        fn admit(&self, _req: &Request) -> bool {
            false
        }
    }

    #[test]
    fn serve_bytes_round_trips_the_whole_path() {
        let store = SlotStore::new();
        let set = Request::Set {
            slot: SLOT.to_string(),
            seed: SEED,
        }
        .encode()
        .unwrap();
        let out = serve_bytes(&store, &TransportIsTheGate, &set).unwrap();
        assert_eq!(Response::decode(&out).unwrap(), Response::Ok);

        let get = Request::Get {
            slot: SLOT.to_string(),
        }
        .encode()
        .unwrap();
        let out = serve_bytes(&store, &TransportIsTheGate, &get).unwrap();
        assert_eq!(Response::decode(&out).unwrap(), Response::Seed(SEED));
    }

    /// A refused caller learns nothing and changes nothing.
    #[test]
    fn a_denied_caller_cannot_read_or_write() {
        let store = SlotStore::new();
        store.serve(&Request::Set {
            slot: SLOT.to_string(),
            seed: SEED,
        });

        for req in [
            Request::Get {
                slot: SLOT.to_string(),
            },
            Request::Set {
                slot: SLOT.to_string(),
                seed: [9u8; 32],
            },
            Request::Clear {
                slot: SLOT.to_string(),
            },
        ] {
            let bytes = req.encode().unwrap();
            let out = serve_bytes(&store, &DenyAll, &bytes).unwrap();
            assert_eq!(Response::decode(&out).unwrap(), Response::Denied);
        }

        // The occupant survived every refused write.
        let get = Request::Get {
            slot: SLOT.to_string(),
        }
        .encode()
        .unwrap();
        let out = serve_bytes(&store, &TransportIsTheGate, &get).unwrap();
        assert_eq!(Response::decode(&out).unwrap(), Response::Seed(SEED));
    }

    /// Health answers even a refused caller — that is what lets a client choose the degraded path
    /// instead of hanging on a broker that would deny it everything else.
    #[test]
    fn health_answers_thru_a_closed_gate() {
        let store = SlotStore::new();
        let bytes = Request::Health.encode().unwrap();
        let out = serve_bytes(&store, &DenyAll, &bytes).unwrap();
        assert_eq!(
            Response::decode(&out).unwrap(),
            Response::Health { ready: true }
        );
    }

    /// Garbage is a transport fault, not a protocol answer.
    #[test]
    fn malformed_bytes_error_rather_than_answering() {
        let store = SlotStore::new();
        assert!(serve_bytes(&store, &TransportIsTheGate, b"not a vsf document").is_err());
        assert!(serve_bytes(&store, &TransportIsTheGate, &[]).is_err());
        // A well-formed *response* is not a request.
        let rsp = Response::Ok.encode().unwrap();
        assert!(serve_bytes(&store, &TransportIsTheGate, &rsp).is_err());
    }

    #[test]
    fn unknown_op_is_rejected() {
        let bytes = VsfBuilder::new()
            .provenance_only()
            .add_section(
                SEC_REQ,
                vec![(F_OP.to_string(), VsfType::a("summon".to_string()))],
            )
            .build()
            .unwrap();
        assert!(Request::decode(&bytes).is_err());
    }
}
