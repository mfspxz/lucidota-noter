//! noter-airgap frame codec as an organelle (codon `na`).
//!
//! The QR-sized transport framing as pure, vault-independent ops:
//! sealed bundles <-> frames. The vault-bound bundle export/import already
//! live on the `noter-notes` organelle (`export_airgap`/`import_airgap`);
//! this unit is the frame codec itself — no vault, no keys, no state.
//! All ops ReadOnly/Proven.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use serde_json::{json, Value};
use std::sync::Arc;

pub const CODON: &str = "na";

fn b64_in(v: &Value, key: &str) -> Result<Vec<u8>, OrganelleError> {
    let s = v
        .get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| OrganelleError::failed(format!("missing string field {key:?}")))?;
    B64.decode(s.as_bytes())
        .map_err(|_| OrganelleError::failed(format!("field {key:?} is not valid base64")))
}

fn frames_in(v: &Value) -> Result<Vec<String>, OrganelleError> {
    v.get("frames")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .ok_or_else(|| OrganelleError::failed("missing frames array"))
}

fn contract(op: &str, description: &str, schema: Value) -> Contract {
    Contract {
        op: op.to_string(),
        description: description.to_string(),
        input_schema: schema,
        mutation_class: None,
        required_capability: None,
    }
}

fn obj(props: Value, required: &[&str]) -> Value {
    json!({ "type": "object", "properties": props, "required": required })
}

pub fn manifest() -> OrganelleManifest {
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: "noter-airgap".to_string(),
        codon: CODON.to_string(),
        version: "0.1.0".to_string(),
        description: "NOTER airgap frame codec: sealed bundles split into QR-sized frames and back. Pure.".to_string(),
        contracts: vec![
            contract("to_frames", "Split a sealed bundle into QR-sized frames.",
                obj(json!({"bundle_b64": {"type": "string"}}), &["bundle_b64"])),
            contract("from_frames", "Reassemble frames into the sealed bundle.",
                obj(json!({"frames": {"type": "array", "items": {"type": "string"}}}), &["frames"])),
            contract("qr_encodable", "Check all frames fit QR capacity.",
                obj(json!({"frames": {"type": "array", "items": {"type": "string"}}}), &["frames"])),
        ],
        authority: Authority {
            mutation_class: MutationClass::ReadOnly,
            declared_valence: Valence::Proven,
            required_capability: None,
            granted_capabilities: vec![],
        },
        transports: Transport::all().to_vec(),
        receipt_policy: ReceiptPolicy {
            content_addressed: true,
            algorithm: RECEIPT_ALGORITHM.to_string(),
            chain: true,
        },
    }
}

pub struct NoterAirgap {
    manifest: OrganelleManifest,
}

pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(NoterAirgap { manifest: manifest() })
}

impl Organelle for NoterAirgap {
    fn manifest(&self) -> OrganelleManifest {
        self.manifest.clone()
    }

    fn handle(
        &self,
        _ctx: &CallContext,
        _host: &dyn HostRef,
        op: &str,
        input: Value,
    ) -> Result<Value, OrganelleError> {
        match op {
            "to_frames" => {
                let bundle = b64_in(&input, "bundle_b64")?;
                Ok(json!({ "frames": noter_airgap::to_frames(&bundle) }))
            }
            "from_frames" => {
                let frames = frames_in(&input)?;
                let bundle = noter_airgap::from_frames(&frames)
                    .map_err(|e| OrganelleError::failed(e.to_string()))?;
                Ok(json!({ "bundle_b64": B64.encode(bundle) }))
            }
            "qr_encodable" => {
                let frames = frames_in(&input)?;
                Ok(json!({ "encodable": noter_airgap::frames_qr_encodable(&frames) }))
            }
            _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use organelle_host::Host;
    use organelle_manifest::validate_manifest_json;

    fn manifest_json() -> Value {
        let txt = include_str!("../../../organelles/noter-airgap.manifest.json");
        serde_json::from_str(txt).expect("manifest JSON parses")
    }

    #[test]
    fn static_manifest_validates() {
        let m = validate_manifest_json(&manifest_json()).expect("static manifest must validate");
        assert_eq!(m.name, "noter-airgap");
        assert_eq!(m.codon, "na");
    }

    #[test]
    fn rust_manifest_matches_static_json() {
        let from_rust = serde_json::to_value(manifest()).unwrap();
        assert_eq!(from_rust, manifest_json(), "Rust manifest() and organelles/*.json must agree");
    }

    #[test]
    fn frame_codec_roundtrips_through_host_with_receipts() {
        let host = Host::new();
        host.register(organelle()).expect("registration must succeed");
        let ctx = CallContext::new("na-test", vec![]);

        let bundle_b64 = B64.encode(b"sealed-bundle-bytes");
        let f = host
            .call(&ctx, "na", "to_frames", json!({"bundle_b64": bundle_b64}))
            .expect("to_frames");
        let frames = f["frames"].as_array().unwrap();
        assert!(!frames.is_empty());

        let q = host
            .call(&ctx, "na", "qr_encodable", json!({"frames": frames}))
            .expect("qr_encodable");
        assert_eq!(q["encodable"], true);

        let b = host
            .call(&ctx, "na", "from_frames", json!({"frames": frames}))
            .expect("from_frames");
        assert_eq!(b["bundle_b64"], Value::String(bundle_b64));

        let n = host.verify_chain().expect("receipt chain must verify");
        assert!(n >= 4, "expected >=4 receipts, got {n}");
    }
}
