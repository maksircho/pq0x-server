use blake3::Hasher;
use pqcrypto_mldsa::mldsa65::{verify_detached_signature, DetachedSignature, PublicKey};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

/// Compute address hash: BLAKE3(IK_pub)
pub fn derive_address_hash(ik_pub_bytes: &[u8]) -> String {
    let mut hasher = Hasher::new();
    hasher.update(ik_pub_bytes);
    hasher.finalize().to_hex().to_string()
}

/// Verify ML-DSA-65 Signature over challenge nonce
pub fn verify_mldsa_signature(
    ik_pub_hex: &str,
    nonce_hex: &str,
    sig_hex: &str,
) -> Result<bool, String> {
    let ik_pub_bytes = hex::decode(ik_pub_hex).map_err(|e| format!("Invalid IK_pub hex: {}", e))?;
    let sig_bytes = hex::decode(sig_hex).map_err(|e| format!("Invalid signature hex: {}", e))?;
    let nonce_bytes = hex::decode(nonce_hex).map_err(|e| format!("Invalid nonce hex: {}", e))?;

    let pk = PublicKey::from_bytes(&ik_pub_bytes)
        .map_err(|_| "Failed to parse ML-DSA-65 public key")?;
    let sig = DetachedSignature::from_bytes(&sig_bytes)
        .map_err(|_| "Failed to parse ML-DSA-65 signature")?;

    match verify_detached_signature(&sig, &nonce_bytes, &pk) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}
