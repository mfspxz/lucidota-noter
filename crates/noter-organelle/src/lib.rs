//! NOTER as an organelle (noter-012).
//!
//! The encrypted notes API behind the organelle-host contract, codon `nt`.
//! Every op is a thin dispatch into the tested `noter-ui` command layer;
//! capability gating, input-schema validation, receipts, and the hash chain
//! are enforced by the host, not reimplemented here.

pub mod airgap;
pub mod crypto;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use noter_crypto::{PublicIdentity, SecretBytes};
use noter_ui::{App, NoteView};
use organelle_host::{CallContext, Host, HostRef, Organelle, OrganelleError};
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Mutex;

pub const CODON: &str = "no";
pub const CAP_READ: &str = "notes.read";
pub const CAP_WRITE: &str = "notes.write";

/// The NOTER organelle. Owns one unlocked vault behind a mutex
/// (`App` is `Send` but `!Sync` because of rusqlite).
pub struct NoterOrganelle {
    app: Mutex<App>,
}

impl NoterOrganelle {
    pub fn open(db_path: &Path, master: SecretBytes) -> Result<Self, noter_ui::AppError> {
        Ok(Self {
            app: Mutex::new(App::open_with_master(db_path, master)?),
        })
    }

    fn with_app<T>(
        &self,
        f: impl FnOnce(&App) -> Result<T, noter_ui::AppError>,
    ) -> Result<T, OrganelleError> {
        let guard = self
            .app
            .lock()
            .map_err(|_| OrganelleError::failed("vault lock poisoned"))?;
        f(&guard).map_err(|e| OrganelleError::failed(e.to_string()))
    }
}

fn str_in(v: &Value, key: &str) -> Result<String, OrganelleError> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| OrganelleError::failed(format!("missing string field {:?}", key)))
}

fn opt_str_vec(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn pub_identity_from(v: &Value) -> Result<PublicIdentity, OrganelleError> {
    let ed = v
        .get("ed25519")
        .and_then(|x| x.as_str())
        .ok_or_else(|| OrganelleError::failed("missing ed25519"))?;
    let x = v
        .get("x25519")
        .and_then(|x| x.as_str())
        .ok_or_else(|| OrganelleError::failed("missing x25519"))?;
    let dechex = |h: &str| -> Result<[u8; 32], OrganelleError> {
        if h.len() != 64 {
            return Err(OrganelleError::failed("pubkey hex must be 64 chars"));
        }
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&h[2 * i..2 * i + 2], 16)
                .map_err(|_| OrganelleError::failed("bad pubkey hex"))?;
        }
        Ok(out)
    };
    Ok(PublicIdentity {
        ed25519: dechex(ed)?,
        x25519: dechex(x)?,
    })
}

fn pub_identity_to_json(p: &PublicIdentity) -> Value {
    let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
    json!({ "ed25519": hex(&p.ed25519), "x25519": hex(&p.x25519) })
}

/// The noter-notes manifest as a free function (also used to generate the
/// static `organelles/noter-notes.manifest.json`; the two must agree).
pub fn notes_manifest() -> OrganelleManifest {
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
            name: "noter-notes".to_string(),
            codon: CODON.to_string(),
            version: "0.1.0".to_string(),
            description: "E2EE encrypted notes: markdown, attachments, graph links, sync.".to_string(),
            contracts: vec![
                ro("device", "This device's id and identity fingerprint.", obj(json!({}), &[])),
                ro("get_note", "Load one note.", obj(json!({"id": {"type": "string"}}), &["id"])),
                ro("list_notes", "List note summaries.", obj(json!({}), &[])),
                ro("search", "Full-text search.", obj(json!({"query": {"type": "string"}}), &["query"])),
                ro("backlinks", "Notes linking to a note.", obj(json!({"id": {"type": "string"}}), &["id"])),
                ro("export_airgap", "Export sync envelopes as QR frames.", obj(json!({"since_ms": {"type": "integer"}}), &[])),
                wr("create_note", "Create a note.", obj(json!({"title": {"type": "string"}, "body_md": {"type": "string"}, "tags": {"type": "array"}}), &["title", "body_md"])),
                wr("update_note", "Update a note.", obj(json!({"id": {"type": "string"}, "title": {"type": "string"}, "body_md": {"type": "string"}, "tags": {"type": "array"}}), &["id", "title", "body_md"])),
                wr("delete_note", "Soft-delete a note.", obj(json!({"id": {"type": "string"}}), &["id"])),
                wr("import_airgap", "Import airgap frames.", obj(json!({"frames": {"type": "array"}}), &["frames"])),
                wr("share_note", "E2EE-share a note with another user.", obj(json!({"note_id": {"type": "string"}, "recipient": {"type": "object"}}), &["note_id", "recipient"])),
                wr("receive_share", "Receive a shared note.", obj(json!({"package_b64": {"type": "string"}, "sender": {"type": "object"}}), &["package_b64", "sender"])),
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

impl Organelle for NoterOrganelle {
    fn manifest(&self) -> OrganelleManifest {
        notes_manifest()
    }

    fn handle(
        &self,
        _ctx: &CallContext,
        _host: &dyn HostRef,
        op: &str,
        input: Value,
    ) -> Result<Value, OrganelleError> {
        match op {
            "device" => self.with_app(|app| {
                Ok(json!({
                    "device_id": app.device_id(),
                    "fingerprint": app.public_identity().fingerprint(),
                    "identity": pub_identity_to_json(&app.public_identity()),
                }))
            }),
            "get_note" => {
                let id = str_in(&input, "id")?;
                self.with_app(|app| Ok(serde_json::to_value(noter_ui::cmd_get_note(app, &id)?).unwrap()))
            }
            "list_notes" => self.with_app(|app| {
                Ok(serde_json::to_value(noter_ui::cmd_list_notes(app)?).unwrap())
            }),
            "search" => {
                let q = str_in(&input, "query")?;
                self.with_app(|app| Ok(serde_json::to_value(noter_ui::cmd_search(app, &q)?).unwrap()))
            }
            "backlinks" => {
                let id = str_in(&input, "id")?;
                self.with_app(|app| {
                    let view: NoteView = noter_ui::cmd_get_note(app, &id)?;
                    Ok(json!({ "id": id, "backlinks": view.backlinks }))
                })
            }
            "export_airgap" => {
                let since = input.get("since_ms").and_then(|v| v.as_i64()).unwrap_or(0);
                self.with_app(|app| {
                    Ok(json!({ "frames": noter_ui::cmd_export_airgap(app, since)? }))
                })
            }
            "create_note" => {
                let title = str_in(&input, "title")?;
                let body = str_in(&input, "body_md")?;
                let tags = opt_str_vec(&input, "tags");
                self.with_app(|app| {
                    Ok(serde_json::to_value(noter_ui::cmd_create_note(app, &title, &body, tags)?).unwrap())
                })
            }
            "update_note" => {
                let id = str_in(&input, "id")?;
                let title = str_in(&input, "title")?;
                let body = str_in(&input, "body_md")?;
                let tags = opt_str_vec(&input, "tags");
                self.with_app(|app| {
                    Ok(serde_json::to_value(noter_ui::cmd_update_note(app, &id, &title, &body, tags)?).unwrap())
                })
            }
            "delete_note" => {
                let id = str_in(&input, "id")?;
                self.with_app(|app| {
                    noter_ui::cmd_delete_note(app, &id)?;
                    Ok(json!({ "deleted": id }))
                })
            }
            "import_airgap" => {
                let frames: Vec<String> = input
                    .get("frames")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                self.with_app(|app| {
                    Ok(serde_json::to_value(noter_ui::cmd_import_airgap(app, &frames)?).unwrap())
                })
            }
            "share_note" => {
                let note_id = str_in(&input, "note_id")?;
                let recipient = pub_identity_from(
                    input.get("recipient").unwrap_or(&Value::Null),
                )?;
                self.with_app(|app| {
                    let bytes = noter_ui::cmd_share_note(app, &note_id, &recipient)?;
                    Ok(json!({ "package_b64": B64.encode(&bytes) }))
                })
            }
            "receive_share" => {
                let b64 = str_in(&input, "package_b64")?;
                let sender =
                    pub_identity_from(input.get("sender").unwrap_or(&Value::Null))?;
                let bytes = B64
                    .decode(b64.as_bytes())
                    .map_err(|_| OrganelleError::failed("bad package_b64"))?;
                self.with_app(|app| {
                    Ok(serde_json::to_value(noter_ui::cmd_receive_share(app, &bytes, &sender)?).unwrap())
                })
            }
            _ => Err(OrganelleError::not_found(format!("unknown op {:?}", op))),
        }
    }
}

/// Convenience: register a NOTER organelle on a host.
pub fn register(host: &Host, db_path: &Path, master: SecretBytes) -> Result<(), String> {
    let org = NoterOrganelle::open(db_path, master).map_err(|e| e.to_string())?;
    host.register(std::sync::Arc::new(org))
        .map_err(|errs| errs.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use organelle_host::{CallContext, Host};

    fn test_host() -> (std::sync::Arc<Host>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "noter-org-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let host = Host::new();
        register(&host, &dir.join("vault.db"), SecretBytes::new([0xCDu8; 32])).unwrap();
        (host, dir)
    }

    fn ctx(caps: &[&str]) -> CallContext {
        CallContext::new(
            "test",
            caps.iter().map(|s| s.to_string()).collect(),
        )
    }

    #[test]
    fn manifest_registers_clean() {
        let (host, _dir) = test_host();
        let manifests = host.list_manifests();
        assert!(manifests.iter().any(|m| m.codon == "no" && m.name == "noter-notes"));
    }

    #[test]
    fn read_op_needs_read_cap() {
        let (host, _dir) = test_host();
        // No caps -> denied.
        let r = host.call(&ctx(&[]), "no", "list_notes", json!({}));
        assert!(r.is_err());
        // Read cap -> ok.
        let r = host.call(&ctx(&["notes.read"]), "no", "list_notes", json!({}));
        assert!(r.unwrap().as_array().unwrap().is_empty());
    }

    #[test]
    fn write_op_needs_write_cap() {
        let (host, _dir) = test_host();
        // Read cap is not enough for writes.
        let r = host.call(
            &ctx(&["notes.read"]),
            "no",
            "create_note",
            json!({"title": "T", "body_md": "b"}),
        );
        assert!(r.is_err());
        // Write cap works.
        let r = host.call(
            &ctx(&["notes.write"]),
            "no",
            "create_note",
            json!({"title": "T", "body_md": "b", "tags": ["x"]}),
        )
        .unwrap();
        assert_eq!(r["title"], "T");
        let id = r["id"].as_str().unwrap().to_string();
        // Read it back via organelle.
        let r = host
            .call(&ctx(&["notes.read"]), "no", "get_note", json!({"id": id}))
            .unwrap();
        assert_eq!(r["body_md"], "b");
    }

    #[test]
    fn search_and_backlinks_through_host() {
        let (host, _dir) = test_host();
        let w = ctx(&["notes.write"]);
        let r = host
            .call(&w, "no", "create_note", json!({"title": "Alpha", "body_md": "zebra stripes"}))
            .unwrap();
        let id = r["id"].as_str().unwrap().to_string();
        host.call(
            &w,
            "no",
            "create_note",
            json!({"title": "Beta", "body_md": format!("see [[{}]]", id)}),
        )
        .unwrap();
        let hits = host
            .call(&ctx(&["notes.read"]), "no", "search", json!({"query": "zebra"}))
            .unwrap();
        assert_eq!(hits.as_array().unwrap().len(), 1);
        let bl = host
            .call(&ctx(&["notes.read"]), "no", "backlinks", json!({"id": id}))
            .unwrap();
        assert_eq!(bl["backlinks"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn input_schema_rejects_bad_input() {
        let (host, _dir) = test_host();
        // missing required body_md -> rejected by host schema validation.
        let r = host.call(
            &ctx(&["notes.write"]),
            "no",
            "create_note",
            json!({"title": "T"}),
        );
        assert!(r.is_err());
        // unknown op -> not found.
        let r = host.call(&ctx(&["notes.write"]), "no", "nope", json!({}));
        assert!(r.is_err());
    }

    #[test]
    fn receipts_chain_verifies() {
        let (host, _dir) = test_host();
        let w = ctx(&["notes.write"]);
        host.call(&w, "no", "create_note", json!({"title": "T", "body_md": "b"}))
            .unwrap();
        host.call(&ctx(&["notes.read"]), "no", "list_notes", json!({}))
            .unwrap();
        let n = host.verify_chain().expect("receipt chain must verify");
        assert!(n >= 3); // registration + 2 invocations
    }

    #[test]
    fn share_roundtrip_through_host() {
        let dir = std::env::temp_dir().join(format!(
            "noter-org-share-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let host_a = Host::new();
        let host_b = Host::new();
        register(&host_a, &dir.join("a.db"), SecretBytes::new([0xA1u8; 32])).unwrap();
        register(&host_b, &dir.join("b.db"), SecretBytes::new([0xB2u8; 32])).unwrap();

        let dev_b: Value = host_b
            .call(&ctx(&["notes.read"]), "no", "device", json!({}))
            .unwrap();
        let bob_pub = dev_b["identity"].clone();
        let dev_a: Value = host_a
            .call(&ctx(&["notes.read"]), "no", "device", json!({}))
            .unwrap();

        let note = host_a
            .call(
                &ctx(&["notes.write"]),
                "no",
                "create_note",
                json!({"title": "Shared", "body_md": "for bob"}),
            )
            .unwrap();
        let pkg = host_a
            .call(
                &ctx(&["notes.write"]),
                "no",
                "share_note",
                json!({"note_id": note["id"], "recipient": bob_pub}),
            )
            .unwrap();
        let got = host_b
            .call(
                &ctx(&["notes.write"]),
                "no",
                "receive_share",
                json!({"package_b64": pkg["package_b64"], "sender": dev_a["identity"]}),
            )
            .unwrap();
        assert_eq!(got["title"], "Shared");
        assert_eq!(got["body_md"], "for bob");
        std::fs::remove_dir_all(&dir).ok();
    }
}

