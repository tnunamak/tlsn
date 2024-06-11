// chatgpt_export_verifier.rs

use std::str;
use std::time::Duration;

use elliptic_curve::pkcs8::DecodePublicKey;
use tlsn_core::proof::{SessionProof, TlsProof};

fn main() {
    // Deserialize the proof
    let proof = std::fs::read_to_string("chatgpt_proof.json").unwrap();
    let proof: TlsProof = serde_json::from_str(proof.as_str()).unwrap();

    let TlsProof {
        session,
        substrings,
    } = proof;

    // Verify the session proof against the Notary's public key
    session
        .verify_with_default_cert_verifier(notary_pubkey())
        .unwrap();

    let SessionProof {
        header,
        session_info,
        ..
    } = session;

    // The time at which the session was recorded
    let time = chrono::DateTime::UNIX_EPOCH + Duration::from_secs(header.time());

    // Verify the substrings proof against the session header.
    let (_, received) = substrings.verify(&header).unwrap();

    // Check if the response size is greater than 1KB
    assert!(received.data().len() > 1024, "Response size is not greater than 1KB");

    println!("-------------------------------------------------------------------");
    println!(
        "Successfully verified that the ZIP file was received from {:?} at {}.",
        session_info.server_name, time
    );
    println!("The response size is: {} bytes", received.data().len());
    println!("-------------------------------------------------------------------");
}

/// Returns a Notary pubkey trusted by this Verifier
fn notary_pubkey() -> p256::PublicKey {
    let pem_file = str::from_utf8(include_bytes!(
        "../../../notary-server/fixture/notary/notary.pub"
    ))
        .unwrap();
    p256::PublicKey::from_public_key_pem(pem_file).unwrap()
}
