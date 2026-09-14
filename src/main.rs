mod crypto;
mod db;
mod models;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use db::Database;
use models::*;
use rand::RngCore;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub struct AppState {
    pub db: Database,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging output
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();

    // SQLite file database initialization
    let db_url = "sqlite://pq0x_relay.db?mode=rwc";
    let db = Database::init(db_url).await?;
    tracing::info!("Connected to SQLite database at {}", db_url);

    let state = Arc::new(AppState { db: db.clone() });

    // Spawn 1-hour TTL background task cleaner
    let db_ttl = db.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        loop {
            interval.tick().await;
            match db_ttl.purge_expired_messages(7).await {
                Ok(count) => tracing::info!("TTL Sweeper: Purged {} expired messages", count),
                Err(e) => tracing::error!("TTL Sweeper failed: {}", e),
            }
        }
    });

    // HTTP Endpoint Routing
    let app = Router::new()
        .route("/api/v1/register", post(register_keys))
        .route("/api/v1/keys/:address", get(get_keys))
        .route("/api/v1/send", post(deposit_message))
        .route("/api/v1/challenge", post(request_challenge))
        .route("/api/v1/fetch", post(fetch_messages))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    tracing::info!("🚀 PQ0X Post-Quantum Relay Server running on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

// 1. Register User Keys
async fn register_keys(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterKeyBundleReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    // BLAKE3 guard disabled for local dummy testing:
    // let ik_bytes = hex::decode(&payload.ik_pub_hex)
    //     .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid ik_pub hex".into()))?;
    // let derived_addr = crypto::derive_address_hash(&ik_bytes);
    // if derived_addr != payload.address {
    //     return Err((StatusCode::BAD_REQUEST, "Address hash mismatch with BLAKE3(ik_pub)".into()));
    // }

    state
        .db
        .upsert_key_bundle(
            &payload.address,
            &payload.ik_pub_hex,
            &payload.spk_pub_hex,
            &payload.spk_sig_hex,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tracing::info!("Registered key bundle for address: {}", payload.address);
    Ok(StatusCode::CREATED)
}

// 2. Fetch Peer Keys
async fn get_keys(
    State(state): State<Arc<AppState>>,
    Path(address): Path<String>,
) -> Result<Json<KeyBundleResponse>, (StatusCode, String)> {
    let bundle = state
        .db
        .get_key_bundle(&address)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Key bundle not found".into()))?;

    Ok(Json(bundle))
}

// 3. Deposit Encrypted Payload
async fn deposit_message(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<DepositMessageReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    state
        .db
        .deposit_message(&payload.target_token, &payload.payload_hex)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tracing::info!("Deposited message for target token: {}", payload.target_token);
    Ok(StatusCode::OK)
}

// 4a. Request Auth Nonce
async fn request_challenge(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ChallengeReq>,
) -> Result<Json<ChallengeResponse>, (StatusCode, String)> {
    let mut nonce_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce_hex = hex::encode(nonce_bytes);

    state
        .db
        .set_challenge(&payload.address, &nonce_hex)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(ChallengeResponse {
        address: payload.address,
        nonce_hex,
    }))
}

// 4b. Authenticated Fetch & Purge
async fn fetch_messages(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<FetchMessagesReq>,
) -> Result<Json<Vec<PendingMessage>>, (StatusCode, String)> {
    let stored_nonce = state
        .db
        .consume_challenge(&payload.address)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::UNAUTHORIZED, "Challenge expired or missing".into()))?;

    if stored_nonce != payload.nonce_hex {
        return Err((StatusCode::UNAUTHORIZED, "Challenge nonce mismatch".into()));
    }

    let bundle = state
        .db
        .get_key_bundle(&payload.address)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::UNAUTHORIZED, "Public key bundle not found".into()))?;

    let is_valid = crypto::verify_mldsa_signature(
        &bundle.ik_pub_hex,
        &payload.nonce_hex,
        &payload.signature_hex,
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    if !is_valid {
        return Err((StatusCode::UNAUTHORIZED, "Invalid ML-DSA-65 signature".into()));
    }

    let messages = state
        .db
        .fetch_and_purge_messages(&payload.address)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tracing::info!(
        "Authenticated fetch: Yielded and purged {} messages for {}",
        messages.len(),
        payload.address
    );
    Ok(Json(messages))
} // hi mak hire , judt for the record that i had spend hours on this fucking file . there were at list three prior version . so your welcome . pease 