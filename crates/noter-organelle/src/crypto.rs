//! noter-crypto as an organelle (codon `ne`).
//!
//! The E2EE crypto core as pure, vault-independent ops: AEAD seal/unseal,
//! identity keygen/sign/verify, sealed-box for recipients. All ops are
//! ReadOnly/Proven — pure functions of their inputs.
//!
//! SECRETS POLICY: key material is caller-supplied per call (base64 inputs)
//! and carried only in `SecretBytes` (zeroizes on drop). Nothing is
//! persisted; receipts carry input/output hashes, never key material.
//! `keygen` returns fresh keypair material to the caller — that is its
//! contract (like any KMS generate op).

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use noter_crypto::{aead, boxcrypt, identity::DeviceIdentity, kdf, PublicIdentity, SecretBytes};
use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use serde_json::{json, Value};
use std::sync::Arc;

pub const CODON: &str = "ne";

fn b64_in(v: &Value, key: &str) -> Result<Vec<u8>, OrganelleError> {
    let s = v
        .get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| OrganelleError::failed(format!("missing string field {key:?}")))?;
    B64.decode(s.as_bytes())
        .map_err(|_| OrganelleError::failed(format!("field {key:?} is not valid base64")))
}

fn key_in(v: &Value, key: &str) -> Result<SecretBytes, OrganelleError> {
    let b = b64_in(v, key)?;
    if b.len() != 32 {
        return Err(OrganelleError::failed(format!("field {key:?} must be 32 bytes")));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&b);
    Ok(SecretBytes::new(arr))
}

fn pub_identity_from(v: &Value) -> Result<PublicIdentity, OrganelleError> {
    let ed = b64_in(v, "ed25519")?;
    let x = b64_in(v, "x25519")?;
    if ed.len() != 32 || x.len() != 32 {
        return Err(OrganelleError::failed("pubkey parts must be 32 bytes each"));
    }
    let mut ed_arr = [0u8; 32];
    let mut x_arr = [0u8; 32];
    ed_arr.copy_from_slice(&ed);
    x_arr.copy_from_slice(&x);
    Ok(PublicIdentity { ed25519: ed_arr, x25519: x_arr })
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
        name: "noter-crypto".to_string(),
        codon: CODON.to_string(),
        version: "0.1.0".to_string(),
        description: "NOTER E2EE crypto core: XChaCha20-Poly1305 AEAD, X25519/Ed25519 identities, Argon2id KDF. Pure ops.".to_string(),
        contracts: vec![
            contract("keygen", "Generate a fresh identity: seed + public parts + fingerprint.",
                obj(json!({}), &[])),
            contract("seal", "AEAD-seal plaintext under a 32-byte key.",
                obj(json!({"key_b64": {"type": "string"}, "plaintext_b64": {"type": "string"}}), &["key_b64", "plaintext_b64"])),
            contract("unseal", "AEAD-open a sealed blob under a 32-byte key.",
                obj(json!({"key_b64": {"type": "string"}, "blob_b64": {"type": "string"}}), &["key_b64", "blob_b64"])),
            contract("sign", "Ed25519-sign a message with an identity seed.",
                obj(json!({"seed_b64": {"type": "string"}, "msg_b64": {"type": "string"}}), &["seed_b64", "msg_b64"])),
            contract("verify", "Ed25519-verify a signature.",
                obj(json!({"ed25519_b64": {"type": "string"}, "msg_b64": {"type": "string"}, "sig_b64": {"type": "string"}}), &["ed25519_b64", "msg_b64", "sig_b64"])),
            contract("fingerprint", "Fingerprint of a public identity.",
                obj(json!({"ed25519_b64": {"type": "string"}, "x25519_b64": {"type": "string"}}), &["ed25519_b64", "x25519_b64"])),
            contract("seal_for", "Sealed-box plaintext for a recipient's public identity.",
                obj(json!({"recipient": {"type": "object"}, "plaintext_b64": {"type": "string"}}), &["recipient", "plaintext_b64"])),
            contract("open_from", "Open a sealed box with our identity seed.",
                obj(json!({"seed_b64": {"type": "string"}, "sealed_b64": {"type": "string"}}), &["seed_b64", "sealed_b64"])),
            contract("derive_master", "Argon2id: derive the master key from passphrase + salt hex. Returns only a fingerprint; the key itself is never emitted.",
                obj(json!({"passphrase": {"type": "string"}, "salt_hex": {"type": "string"}}), &["passphrase", "salt_hex"])),
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

pub struct NoterCrypto {
    manifest: OrganelleManifest,
}

pub fn organelle() -> Arc<dyn Organelle> {
    Arc::new(NoterCrypto { manifest: manifest() })
}

fn identity_from_seed(v: &Value) -> Result<DeviceIdentity, OrganelleError> {
    let seed = b64_in(v, "seed_b64")?;
    if seed.len() != 64 {
        return Err(OrganelleError::failed("seed_b64 must be 64 bytes"));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&seed);
    DeviceIdentity::from_seed_bytes(&arr).map_err(|e| OrganelleError::failed(e.to_string()))
}

impl Organelle for NoterCrypto {
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
            "keygen" => {
                let id = DeviceIdentity::generate();
                let seed = id.export_seed();
                let pub_id = id.public();
                Ok(json!({
                    "seed_b64": B64.encode(seed.as_bytes()),
                    "ed25519_b64": B64.encode(pub_id.ed25519),
                    "x25519_b64": B64.encode(pub_id.x25519),
                    "fingerprint": pub_id.fingerprint(),
                }))
            }
            "seal" => {
                let key = key_in(&input, "key_b64")?;
                let pt = b64_in(&input, "plaintext_b64")?;
                Ok(json!({ "blob_b64": B64.encode(aead::encrypt(&key, &pt)) }))
            }
            "unseal" => {
                let key = key_in(&input, "key_b64")?;
                let blob = b64_in(&input, "blob_b64")?;
                let pt = aead::decrypt(&key, &blob).map_err(|e| OrganelleError::failed(e.to_string()))?;
                Ok(json!({ "plaintext_b64": B64.encode(pt) }))
            }
            "sign" => {
                let id = identity_from_seed(&input)?;
                let msg = b64_in(&input, "msg_b64")?;
                Ok(json!({ "sig_b64": B64.encode(id.sign(&msg)) }))
            }
            "verify" => {
                let ed = b64_in(&input, "ed25519_b64")?;
                let msg = b64_in(&input, "msg_b64")?;
                let sig = b64_in(&input, "sig_b64")?;
                if ed.len() != 32 || sig.len() != 64 {
                    return Err(OrganelleError::failed("bad key/sig lengths"));
                }
                let mut ed_arr = [0u8; 32];
                let mut sig_arr = [0u8; 64];
                ed_arr.copy_from_slice(&ed);
                sig_arr.copy_from_slice(&sig);
                let pub_id = PublicIdentity { ed25519: ed_arr, x25519: [0u8; 32] };
                match pub_id.verify(&msg, &sig_arr) {
                    Ok(()) => Ok(json!({ "valid": true })),
                    Err(_) => Ok(json!({ "valid": false })),
                }
            }
            "fingerprint" => {
                let ed = b64_in(&input, "ed25519_b64")?;
                let x = b64_in(&input, "x25519_b64")?;
                if ed.len() != 32 || x.len() != 32 {
                    return Err(OrganelleError::failed("pubkey parts must be 32 bytes each"));
                }
                let mut ed_arr = [0u8; 32];
                let mut x_arr = [0u8; 32];
                ed_arr.copy_from_slice(&ed);
                x_arr.copy_from_slice(&x);
                let id = PublicIdentity { ed25519: ed_arr, x25519: x_arr };
                Ok(json!({ "fingerprint": id.fingerprint() }))
            }
            "seal_for" => {
                let recipient = pub_identity_from(input.get("recipient").unwrap_or(&Value::Null))?;
                let pt = b64_in(&input, "plaintext_b64")?;
                Ok(json!({ "sealed_b64": B64.encode(boxcrypt::seal_for(&recipient, &pt)) }))
            }
            "open_from" => {
                let id = identity_from_seed(&input)?;
                let sealed = b64_in(&input, "sealed_b64")?;
                let pt = boxcrypt::open_from(id.x25519_secret(), &sealed)
                    .map_err(|e| OrganelleError::failed(e.to_string()))?;
                Ok(json!({ "plaintext_b64": B64.encode(pt) }))
            }
            "derive_master" => {
                let pass = input.get("passphrase").and_then(|x| x.as_str())
                    .ok_or_else(|| OrganelleError::failed("missing string field \"passphrase\""))?;
                let salt_hex = input.get("salt_hex").and_then(|x| x.as_str())
                    .ok_or_else(|| OrganelleError::failed("missing string field \"salt_hex\""))?;
                let salt = kdf::Salt::from_hex(salt_hex).map_err(|e| OrganelleError::failed(e.to_string()))?;
                let master = kdf::derive_master_key(pass, &salt).map_err(|e| OrganelleError::failed(e.to_string()))?;
                // Never emit the key: return a fingerprint of the derivation.
                use sha2::{Digest, Sha256};
                let fp = B64.encode(Sha256::digest(master.as_bytes()));
                drop(master);
                Ok(json!({ "derived": true, "fingerprint_sha256_b64": fp }))
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
        let txt = include_str!("../../../organelles/noter-crypto.manifest.json");
        serde_json::from_str(txt).expect("manifest JSON parses")
    }

    #[test]
    fn static_manifest_validates() {
        let m = validate_manifest_json(&manifest_json()).expect("static manifest must validate");
        assert_eq!(m.name, "noter-crypto");
        assert_eq!(m.codon, "ne");
    }

    #[test]
    fn rust_manifest_matches_static_json() {
        let from_rust = serde_json::to_value(manifest()).unwrap();
        assert_eq!(from_rust, manifest_json(), "Rust manifest() and organelles/*.json must agree");
    }

    #[test]
    fn crypto_roundtrips_through_host_with_receipts() {
        let host = Host::new();
        host.register(organelle()).expect("registration must succeed");
        let ctx = CallContext::new("ne-test", vec![]);

        // keygen -> seal -> unseal roundtrip through the real AEAD
        let kg = host.call(&ctx, "ne", "keygen", json!({})).expect("keygen");
        assert!(kg.output["fingerprint"].as_str().unwrap().len() > 0);
        let key_b64 = B64.encode([0x11u8; 32]);
        let sealed = host.call(&ctx, "ne", "seal", json!({"key_b64": key_b64, "plaintext_b64": B64.encode(b"hello noter")})).expect("seal");
        let opened = host.call(&ctx, "ne", "unseal", json!({"key_b64": key_b64, "blob_b64": sealed.output["blob_b64"]})).expect("unseal");
        assert_eq!(opened.output["plaintext_b64"], Value::String(B64.encode(b"hello noter")));

        // wrong key -> clean failure, still receipted
        assert!(host.call(&ctx, "ne", "unseal", json!({"key_b64": B64.encode([0x22u8; 32]), "blob_b64": sealed.output["blob_b64"]})).is_err());

        // sign -> verify roundtrip through the real Ed25519
        let seed_b64 = kg.output["seed_b64"].as_str().unwrap();
        let sig = host.call(&ctx, "ne", "sign", json!({"seed_b64": seed_b64, "msg_b64": B64.encode(b"msg")})).expect("sign");
        let v = host.call(&ctx, "ne", "verify", json!({
            "ed25519_b64": kg.output["ed25519_b64"], "msg_b64": B64.encode(b"msg"), "sig_b64": sig.output["sig_b64"]})).expect("verify");
        assert_eq!(v.output["valid"], true);
        let v2 = host.call(&ctx, "ne", "verify", json!({
            "ed25519_b64": kg.output["ed25519_b64"], "msg_b64": B64.encode(b"tampered"), "sig_b64": sig.output["sig_b64"]})).expect("verify2");
        assert_eq!(v2.output["valid"], false);

        // sealed-box roundtrip through the real X25519
        let sb = host.call(&ctx, "ne", "seal_for", json!({
            "recipient": {"ed25519": kg.output["ed25519_b64"], "x25519": kg.output["x25519_b64"]},
            "plaintext_b64": B64.encode(b"for you")})).expect("seal_for");
        let op = host.call(&ctx, "ne", "open_from", json!({"seed_b64": seed_b64, "sealed_b64": sb.output["sealed_b64"]})).expect("open_from");
        assert_eq!(op.output["plaintext_b64"], Value::String(B64.encode(b"for you")));

        let n = host.verify_chain().expect("receipt chain must verify");
        assert!(n >= 8, "expected >=8 receipts, got {n}");
    }
}
