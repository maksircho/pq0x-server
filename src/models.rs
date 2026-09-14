use serde::{Deserialize, Serialize};

/// Payload sent by client to register identity & prekeys
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterKeyBundleReq {
    pub address: String,       // Hex string: BLAKE3(IK_pub)
    pub ik_pub_hex: String,    // ML-DSA-65 Public Identity Key (Hex)
    pub spk_pub_hex: String,   // ML-KEM-768 Signed Prekey (Hex)
    pub spk_sig_hex: String,   // ML-DSA-65 signature over SPK (Hex)
}

/// Key bundle returned when a user requests peer keys
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct KeyBundleResponse {
    pub address: String,
    pub ik_pub_hex: String,
    pub spk_pub_hex: String,
    pub spk_sig_hex: String,
}

/// Encrypted message payload deposited by a sender
#[derive(Debug, Serialize, Deserialize)]
pub struct DepositMessageReq {
    pub target_token: String,  // Target address hash or routing token
    pub payload_hex: String,   // Encrypted payload (Hex)
}

/// Message payload returned during authenticated fetch
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct PendingMessage {
    pub id: i64,
    pub target_token: String,
    pub payload_hex: String,
    pub created_at: String,
}

/// Auth challenge request
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeReq {
    pub address: String,
}

/// Auth challenge response
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub address: String,
    pub nonce_hex: String,
}

/// Client signature proof submission to fetch pending messages
#[derive(Debug, Serialize, Deserialize)]
pub struct FetchMessagesReq {
    pub address: String,
    pub nonce_hex: String,
    pub signature_hex: String, // ML-DSA-65 signature over nonce_hex
}
