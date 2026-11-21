//! legallibrary as a NOTER plugin (codon `ls`).
//!
//! The legal-authority engine behind the organelle-host contract: resolve,
//! rank, attach provenance, cite — over a corpus loaded from disk and
//! verified at open (wsign Ed25519 signature over the file bytes, source
//! ids via `u5::load_corpus`, provenance hashes against the raw-file
//! manifest). Capability gating, input-schema validation, receipts, and
//! the hash chain are enforced by the host, not reimplemented here.
//!
//! The corpus is a signed artifact: `open`/`register` take the trusted
//! wsign public key (hex) and refuse unsigned or mis-signed corpora.
//! There is no unverified open path.
//!
//! The tier-C gate: provenance may be attached ONLY to Commentary-tier
//! sources. Official sources carry publisher provenance from ingest; a
//! caller must not overwrite it. Attached records live in memory for the
//! plugin's lifetime — they never rewrite the signed corpus file.

use legal_authority_engine::{u2, u3, u4, u5};
use organelle_host::{CallContext, Host, HostRef, Organelle, OrganelleError};
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

pub const CODON: &str = "ls";
pub const CAP_READ: &str = "legal.read";
pub const CAP_WRITE: &str = "legal.write";

/// The legal-authority organelle. Owns the loaded corpus (read-only after
/// open) plus the in-memory map of caller-attached provenance records.
pub struct LegalAuthorityOrganelle {
    corpus: Arc<u5::Corpus>,
    corpus_json: String,
    attached: Mutex<HashMap<String, u3::ProvenanceRecord>>,
}

impl LegalAuthorityOrganelle {
    /// Load and verify a corpus file. The wsign signature (`<path>.sig`
    /// sidecar, Ed25519 over the raw file bytes) is verified against the
    /// trusted `pubkey_hex` first; `u5::load_corpus` then recomputes every
    /// source id; the raw-file manifest (`raw/MANIFEST.json` next to the
    /// corpus) is then checked against every source's provenance hash.
    /// A corpus without a manifest (test corpora) skips the hash check.
    /// A corpus without a valid signature never loads (R14).
    pub fn open(corpus_path: &Path, pubkey_hex: &str) -> Result<Self, String> {
        let bytes = std::fs::read(corpus_path)
            .map_err(|e| format!("cannot read corpus {}: {e}", corpus_path.display()))?;
        let mut sig_path = corpus_path.as_os_str().to_owned();
        sig_path.push(".sig");
        let sig_text = std::fs::read_to_string(&sig_path).map_err(|e| {
            format!(
                "cannot read corpus signature {}: {e} — the corpus is a signed artifact; unsigned corpora do not load",
                sig_path.display()
            )
        })?;
        let json = String::from_utf8(bytes)
            .map_err(|e| format!("corpus is not valid UTF-8: {e}"))?;
        let corpus = u5::load_corpus_signed(&json, &sig_text, pubkey_hex)
            .map_err(|e| e.to_string())?;
        if let Some(dir) = corpus_path.parent() {
            let manifest_path = dir.join("raw").join("MANIFEST.json");
            if manifest_path.exists() {
                let mjson = std::fs::read_to_string(&manifest_path)
                    .map_err(|e| format!("cannot read manifest {}: {e}", manifest_path.display()))?;
                let m: Value = serde_json::from_str(&mjson)
                    .map_err(|e| format!("invalid manifest JSON: {e}"))?;
                let mut shas: HashMap<String, String> = HashMap::new();
                for f in m["files"].as_array().cloned().unwrap_or_default() {
                    if let (Some(url), Some(sha)) =
                        (f["source_url"].as_str(), f["sha256"].as_str())
                    {
                        shas.insert(url.to_string(), sha.to_string());
                    }
                }
                for s in &corpus.sources {
                    if let Some(p) = &s.provenance {
                        let want = shas.get(&p.official_url).ok_or_else(|| {
                            format!(
                                "source {} s.{}: provenance URL {} not in raw manifest",
                                s.instrument, s.section, p.official_url
                            )
                        })?;
                        if *want != p.content_sha256 {
                            return Err(format!(
                                "source {} s.{}: provenance hash mismatch (manifest {}, corpus {})",
                                s.instrument, s.section, want, p.content_sha256
                            ));
                        }
                    }
                }
            }
        }
        Ok(Self {
            corpus: Arc::new(corpus),
            corpus_json: json,
            attached: Mutex::new(HashMap::new()),
        })
    }

    fn find(&self, id: &str) -> Result<&u5::Source, OrganelleError> {
        self.corpus
            .sources
            .iter()
            .find(|s| s.id == id)
            .ok_or_else(|| OrganelleError::not_found(format!("no source with id {id}")))
    }
}

fn str_in(v: &Value, key: &str) -> Result<String, OrganelleError> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| OrganelleError::failed(format!("missing string field {:?}", key)))
}

/// The membrane: one unit's Source becomes another unit's Source via JSON.
/// The units' Source types are serde-identical (same 9 fields, same order).
fn via_json<T: Serialize, U: DeserializeOwned>(v: &T) -> Result<U, OrganelleError> {
    let json = serde_json::to_string(v).map_err(|e| OrganelleError::failed(e.to_string()))?;
    serde_json::from_str(&json).map_err(|e| OrganelleError::failed(format!("membrane: {e}")))
}

/// The legal-authority manifest as a free function (also used to generate
/// the static `organelles/legal-authority.manifest.json`; the two must agree).
pub fn legal_authority_manifest() -> OrganelleManifest {
    let ro = |op: &str, desc: &str, schema: Value| Contract {
        op: op.to_string(),
        description: desc.to_string(),
        input_schema: schema,
        mutation_class: Some(MutationClass::ReadOnly),
        required_capability: Some(CAP_READ.to_string()),
    };
    let wr = |op: &str, desc: &str, schema: Value| Contract {
        op: op.to_string(),
        description: desc.to_string(),
        input_schema: schema,
        mutation_class: Some(MutationClass::Write),
        required_capability: Some(CAP_WRITE.to_string()),
    };
    let obj = |props: Value, required: &[&str]| {
        json!({
            "type": "object",
            "properties": props,
            "required": required,
        })
    };
    OrganelleManifest {
        schema_version: "1".to_string(),
        name: "legal-authority".to_string(),
        codon: CODON.to_string(),
        version: "0.1.0".to_string(),
        description: "Legal authority: resolve, rank, attach provenance, cite. Official BC/Canada statutes first, provenance always.".to_string(),
        contracts: vec![
            ro("resolve_source", "Resolve a query against the corpus (top 10 hits, ranked).", obj(json!({"query": {"type": "string"}, "jurisdiction": {"type": "string"}}), &["query"])),
            ro("rank_authority", "Rank a list of sources by authority for a jurisdiction.", obj(json!({"sources": {"type": "array"}, "jurisdiction": {"type": "string"}}), &["sources"])),
            ro("cite", "Build a citation for one source.", obj(json!({"source_id": {"type": "string"}}), &["source_id"])),
            wr("attach_provenance", "Attach a caller-declared provenance record to a Commentary-tier source. Refused for official sources.", obj(json!({"source_id": {"type": "string"}, "provenance": {"type": "object"}}), &["source_id", "provenance"])),
        ],
        authority: Authority {
            mutation_class: MutationClass::Write,
            declared_valence: Valence::Candidate,
            required_capability: Some(CAP_WRITE.to_string()),
            granted_capabilities: vec![],
        },
        transports: Transport::all().to_vec(),
        receipt_policy: ReceiptPolicy {
            content_addressed: true,
            algorithm: "sha256".to_string(),
            chain: true,
        },
    }
}

impl Organelle for LegalAuthorityOrganelle {
    fn manifest(&self) -> OrganelleManifest {
        legal_authority_manifest()
    }

    fn handle(
        &self,
        _ctx: &CallContext,
        _host: &dyn HostRef,
        op: &str,
        input: Value,
    ) -> Result<Value, OrganelleError> {
        match op {
            "resolve_source" => {
                let query = str_in(&input, "query")?;
                let jurisdiction = input
                    .get("jurisdiction")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let hits = u5::resolve(&query, &self.corpus_json, &jurisdiction)
                    .map_err(|e| OrganelleError::failed(e.to_string()))?;
                Ok(json!({ "hits": hits }))
            }
            "rank_authority" => {
                let sources: Vec<u5::Source> = input
                    .get("sources")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .ok_or_else(|| OrganelleError::failed("sources must be an array of Source objects"))?;
                // Membrane check (R19): a supplied tier must agree with the
                // tier its provenance URL actually carries. A caller may
                // not launder a commentary URL into an official rank (or
                // demote an official one). Sources without provenance carry
                // no URL evidence and skip the check.
                for s in &sources {
                    if let Some(p) = &s.provenance {
                        let actual = u5::tier_of_url(&p.official_url);
                        if actual != s.tier {
                            return Err(OrganelleError::failed(format!(
                                "tier mismatch for source {} s.{}: declared {:?} but URL {} carries {:?}",
                                s.instrument, s.section, s.tier, p.official_url, actual
                            )));
                        }
                    }
                }
                let jurisdiction = input
                    .get("jurisdiction")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let as_u2: Vec<u2::Source> =
                    sources.iter().map(via_json).collect::<Result<Vec<_>, _>>()?;
                let ranked = u2::rank_sources(&as_u2, &jurisdiction);
                let back: Vec<u5::Source> =
                    ranked.iter().map(via_json).collect::<Result<Vec<_>, _>>()?;
                Ok(json!({ "sources": back }))
            }
            "cite" => {
                let id = str_in(&input, "source_id")?;
                let source = self.find(&id)?;
                let mut as_u4: u4::Source = via_json(source)?;
                // A caller-attached record (tier-C only) takes precedence
                // over the corpus provenance for citation purposes.
                if let Ok(guard) = self.attached.lock() {
                    if let Some(rec) = guard.get(&id) {
                        as_u4.provenance = Some(via_json(rec)?);
                    }
                }
                let citation =
                    u4::build_citation(&as_u4).map_err(|e| OrganelleError::failed(e.to_string()))?;
                Ok(serde_json::to_value(citation).unwrap())
            }
            "attach_provenance" => {
                let id = str_in(&input, "source_id")?;
                let prov = input
                    .get("provenance")
                    .cloned()
                    .unwrap_or(Value::Null);
                let publisher = str_in(&prov, "publisher")?;
                let official_url = str_in(&prov, "official_url")?;
                let retrieved_at = str_in(&prov, "retrieved_at")?;
                let currency_date = str_in(&prov, "currency_date")?;
                let content = str_in(&prov, "content")?;
                let source = self.find(&id)?;
                // Tier-C gate: official sources carry publisher provenance
                // from ingest; attaching to them would forge authority.
                if !matches!(source.tier, u5::AuthorityTier::Commentary) {
                    return Err(OrganelleError::denied(format!(
                        "attach refused: source {} is {:?}, not Commentary; official provenance comes from the publisher at ingest",
                        source.section, source.tier
                    )));
                }
                let record = u3::attach(
                    &id,
                    &publisher,
                    &official_url,
                    &retrieved_at,
                    &currency_date,
                    &content,
                )
                .map_err(|e| OrganelleError::failed(e.to_string()))?;
                self.attached
                    .lock()
                    .map_err(|_| OrganelleError::failed("attached map lock poisoned"))?
                    .insert(id, record.clone());
                Ok(serde_json::to_value(record).unwrap())
            }
            _ => Err(OrganelleError::not_found(format!("unknown op {:?}", op))),
        }
    }
}

/// Convenience: register a legal-authority organelle on a host.
/// `pubkey_hex` is the trusted wsign Ed25519 public key (hex) for the corpus.
pub fn register(host: &Host, corpus_path: &Path, pubkey_hex: &str) -> Result<(), String> {
    let org = LegalAuthorityOrganelle::open(corpus_path, pubkey_hex)?;
    host.register(std::sync::Arc::new(org))
        .map_err(|errs| errs.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use organelle_host::{CallContext, Host};

    /// The WSIG public key that signed corpus-v1.json (~/workspace/proof-ledger/WSIG_PUBKEY).
    const WSIG_PUBKEY_HEX: &str =
        "8577c1955dfacf6a1100f85d33b8c52c9aa974720b4621056c26d4151eb41a5f";

    fn real_corpus() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../legallibrary-organelle/corpus/corpus-v1.json")
    }

    fn static_manifest_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../organelles/legal-authority.manifest.json")
    }

    fn test_host() -> std::sync::Arc<Host> {
        let host = Host::new();
        register(&host, &real_corpus(), WSIG_PUBKEY_HEX).unwrap();
        host
    }

    fn ctx(caps: &[&str]) -> CallContext {
        CallContext::new("test", caps.iter().map(|s| s.to_string()).collect())
    }

    /// Regenerate the static manifest file: run with
    /// `cargo test -p noter-legal-authority print_manifest -- --ignored --nocapture`
    /// and save the printed line to `organelles/legal-authority.manifest.json`.
    #[test]
    #[ignore]
    fn print_manifest() {
        println!("{}", serde_json::to_string(&legal_authority_manifest()).unwrap());
    }

    #[test]
    fn manifest_registers_clean() {
        let host = test_host();
        let manifests = host.list_manifests();
        assert!(manifests
            .iter()
            .any(|m| m.codon == "ls" && m.name == "legal-authority"));
    }

    #[test]
    fn static_manifest_agrees() {
        let on_disk = std::fs::read_to_string(static_manifest_path())
            .expect("organelles/legal-authority.manifest.json must exist");
        assert_eq!(
            on_disk.trim(),
            serde_json::to_string(&legal_authority_manifest()).unwrap()
        );
    }

    #[test]
    fn read_op_needs_read_cap() {
        let host = test_host();
        let r = host.call(&ctx(&[]), "ls", "resolve_source", json!({"query": "equality"}));
        assert!(r.is_err());
        let r = host
            .call(&ctx(&["legal.read"]), "ls", "resolve_source", json!({"query": "equality"}))
            .unwrap();
        assert!(!r.output["hits"].as_array().unwrap().is_empty());
    }

    #[test]
    fn resolve_section_15_through_host() {
        let host = test_host();
        let r = host
            .call(
                &ctx(&["legal.read"]),
                "ls",
                "resolve_source",
                json!({"query": "section 15 equality", "jurisdiction": "CA"}),
            )
            .unwrap();
        let top = &r.output["hits"][0]["source"];
        assert_eq!(top["section"], "15(1)");
        assert!(top["instrument"].as_str().unwrap().contains("Charter"));
    }

    #[test]
    fn cite_through_host() {
        let host = test_host();
        let r = host
            .call(
                &ctx(&["legal.read"]),
                "ls",
                "resolve_source",
                json!({"query": "section 7 life liberty", "jurisdiction": "CA"}),
            )
            .unwrap();
        let id = r.output["hits"][0]["source"]["id"].as_str().unwrap().to_string();
        let c = host
            .call(&ctx(&["legal.read"]), "ls", "cite", json!({"source_id": id}))
            .unwrap();
        assert!(c.output["short_cite"].as_str().unwrap().contains("7"));
        assert!(c.output["url"].as_str().unwrap().contains("lois.justice.gc.ca"));
    }

    #[test]
    fn rank_through_host() {
        let host = test_host();
        let r = host
            .call(
                &ctx(&["legal.read"]),
                "ls",
                "resolve_source",
                json!({"query": "tenancy", "jurisdiction": "BC"}),
            )
            .unwrap();
        let sources: Vec<Value> = r.output["hits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h["source"].clone())
            .collect();
        let ranked = host
            .call(
                &ctx(&["legal.read"]),
                "ls",
                "rank_authority",
                json!({"sources": sources, "jurisdiction": "BC"}),
            )
            .unwrap();
        let out = ranked.output["sources"].as_array().unwrap();
        assert_eq!(out.len(), sources.len());
        assert_eq!(out[0]["jurisdiction"], "BC");
    }

    #[test]
    fn attach_denied_on_official_source() {
        let host = test_host();
        let r = host
            .call(
                &ctx(&["legal.read"]),
                "ls",
                "resolve_source",
                json!({"query": "section 7 life liberty", "jurisdiction": "CA"}),
            )
            .unwrap();
        let id = r.output["hits"][0]["source"]["id"].as_str().unwrap().to_string();
        let err = host
            .call(
                &ctx(&["legal.write"]),
                "ls",
                "attach_provenance",
                json!({"source_id": id, "provenance": {
                    "publisher": "Someone",
                    "official_url": "https://example.com/x",
                    "retrieved_at": "2026-11-20",
                    "currency_date": "2026-11-20",
                    "content": "text"
                }}),
            )
            .unwrap_err();
        assert!(err.to_string().contains("not Commentary"), "{err}");
    }

    #[test]
    fn attach_allowed_on_commentary_then_cites() {
        // Synthetic corpus: one official Charter source + one commentary
        // source with no provenance yet.
        let all = u5::test_sources();
        let charter7 = all
            .iter()
            .find(|s| s.section == "7")
            .expect("test_sources must include Charter s.7")
            .clone();
        let mut commentary = all
            .iter()
            .find(|s| matches!(s.tier, u5::AuthorityTier::Commentary))
            .expect("test_sources must include a commentary source")
            .clone();
        commentary.provenance = None;
        let corpus = u5::Corpus {
            version: "1".to_string(),
            sources: vec![charter7, commentary.clone()],
        };
        let dir = std::env::temp_dir().join(format!(
            "noter-legal-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("corpus.json");
        let json = serde_json::to_string(&corpus).unwrap();
        std::fs::write(&path, &json).unwrap();
        // Sign the synthetic corpus with an ephemeral key (open() is
        // fail-closed: no valid .sig, no load).
        let id = noter_crypto::DeviceIdentity::generate();
        let sig = id.sign(json.as_bytes());
        let sig_hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
        let mut sig_path = path.as_os_str().to_owned();
        sig_path.push(".sig");
        std::fs::write(&sig_path, format!("wsig1:testkey:{sig_hex}")).unwrap();
        let pk_hex: String = id
            .public()
            .ed25519
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        let host = Host::new();
        register(&host, &path, &pk_hex).unwrap();
        let id = commentary.id.clone();
        let attached = host
            .call(
                &ctx(&["legal.write"]),
                "ls",
                "attach_provenance",
                json!({"source_id": id, "provenance": {
                    "publisher": "Test Commentator",
                    "official_url": "https://example.com/commentary",
                    "retrieved_at": "2026-11-20",
                    "currency_date": "2026-11-20",
                    "content": "the commentary text"
                }}),
            )
            .unwrap();
        assert_eq!(attached.output["publisher"], "Test Commentator");
        // Citing now uses the attached record.
        let c = host
            .call(&ctx(&["legal.read"]), "ls", "cite", json!({"source_id": id}))
            .unwrap();
        assert_eq!(c.output["url"], "https://example.com/commentary");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn codons_coexist_with_noter_notes() {
        use noter_crypto::SecretBytes;
        let dir = std::env::temp_dir().join(format!(
            "noter-legal-coexist-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let host = Host::new();
        noter_organelle::register(&host, &dir.join("vault.db"), SecretBytes::new([0xCDu8; 32]))
            .unwrap();
        register(&host, &real_corpus(), WSIG_PUBKEY_HEX).unwrap();
        let codons: Vec<String> = host.list_manifests().iter().map(|m| m.codon.clone()).collect();
        assert!(codons.contains(&"no".to_string()), "{codons:?}");
        assert!(codons.contains(&"ls".to_string()), "{codons:?}");
        // Both answer through the same host.
        host.call(&ctx(&["notes.read"]), "no", "list_notes", json!({})).unwrap();
        let r = host
            .call(&ctx(&["legal.read"]), "ls", "resolve_source", json!({"query": "equality"}))
            .unwrap();
        assert!(!r.output["hits"].as_array().unwrap().is_empty());
        let n = host.verify_chain().expect("receipt chain must verify");
        assert!(n >= 3);
        std::fs::remove_dir_all(&dir).ok();
    }
}
