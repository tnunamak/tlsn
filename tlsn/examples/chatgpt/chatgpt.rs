// chatgpt_export_prover.rs

use std::ops::Range;
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tlsn_core::proof::TlsProof;
use tlsn_examples::request_notarization;
use tokio::io::AsyncWriteExt as _;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;

use tlsn_prover::tls::{Prover, ProverConfig};
use tlsn_prover::tls::state::Notarize;

// Setting of the application server
const SERVER_DOMAIN: &str = "proddatamgmtqueue.blob.core.windows.net";

// Setting of the notary server
const NOTARY_HOST: &str = "127.0.0.1";
const NOTARY_PORT: u16 = 7047;

// Configuration of notarization
const NOTARY_MAX_SENT: usize = 1 << 12;
const NOTARY_MAX_RECV: usize = 1 << 21; // Increased to handle larger ZIP file

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // get export_url from a realtime prompt for user input
    // let mut export_url = String::new();
    // println!("Enter the ChatGPT export URL: ");
    // std::io::stdin().read_line(&mut export_url).unwrap();
    // export_url = export_url.trim().to_string();
    // let export_url = export_url.as_str();
    let export_url: &str ="https://proddatamgmtqueue.blob.core.windows.net/exportcontainer/8c94d6508a25ad315b20c3981e842047ddac165c882be2e54c9f822c957cd703-2024-06-09-18-16-38.zip?se=2024-06-10T18%3A16%3A38Z&sp=r&sv=2023-11-03&sr=b&sig=gRTXqmlARB8k09mKjUHmd8XefGP0qAoaeu78rEZJZBA%3D";

    // ChatGPT export URL
    let url = url::Url::parse(export_url).unwrap();
    // This contains auth info and should be redacted
    let query_string = url.query().unwrap();
    // Validate that the domain matches the SERVER_DOMAIN
    assert_eq!(url.domain().unwrap(), SERVER_DOMAIN);
    println!("Export URL: {}", export_url);

    let (notary_tls_socket, session_id) = request_notarization(
        NOTARY_HOST,
        NOTARY_PORT,
        Some(NOTARY_MAX_SENT),
        Some(NOTARY_MAX_RECV),
    )
        .await;

    // Basic default prover config using the session_id returned from /session endpoint
    let config = ProverConfig::builder()
        .id(session_id)
        .server_dns(SERVER_DOMAIN)
        .max_recv_data(NOTARY_MAX_RECV)
        .max_sent_data(NOTARY_MAX_SENT)
        // .max_transcript_size(NOTARY_MAX_TRANSCRIPT_SIZE)
        .build()
        .unwrap();

    // Create a new prover and set up the MPC backend.
    let prover = Prover::new(config)
        .setup(notary_tls_socket.compat())
        .await
        .unwrap();

    let client_socket = tokio::net::TcpStream::connect((SERVER_DOMAIN, 443))
        .await
        .unwrap();

    // Bind the Prover to server connection
    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();

    // Spawn the Prover to be run concurrently
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the TLS connection
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_connection.compat()))
            .await
            .unwrap();

    // Spawn the HTTP task to be run concurrently
    tokio::spawn(connection);

    // Build the HTTP request to fetch the ChatGPT export ZIP file
    let request = Request::builder()
        .uri(export_url)
        .header("Host", SERVER_DOMAIN)
        .header("Accept", "*/*")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .body(Empty::<Bytes>::new())
        .unwrap();

    debug!("Sending request");

    let response = request_sender.send_request(request).await.unwrap();

    debug!("Sent request");

    assert!(response.status() == StatusCode::OK, "{}", response.status());

    debug!("Request OK");

    // // Collect the response body (ZIP file)
    let zip_file = response.into_body().collect().await.unwrap().to_bytes();

    // The Prover task should be done now, so we can grab it.
    let prover = prover_task.await.unwrap().unwrap();

    // Prepare for notarization
    let prover = prover.start_notarize();

    // Build proof with redactions
    let proof = build_proof_with_redactions(prover, &zip_file, query_string).await;

    // Dump the proof to a file.
    let mut file = tokio::fs::File::create("chatgpt_proof.json")
        .await
        .unwrap();
    file.write_all(serde_json::to_string_pretty(&proof).unwrap().as_bytes())
        .await
        .unwrap();
}

fn find_ranges(seq: &[u8], sub_seq: &[&[u8]]) -> (Vec<Range<usize>>, Vec<Range<usize>>) {
    let mut private_ranges = Vec::new();
    for s in sub_seq {
        for (idx, w) in seq.windows(s.len()).enumerate() {
            if w == *s {
                private_ranges.push(idx..(idx + w.len()));
            }
        }
    }

    let mut sorted_ranges = private_ranges.clone();
    sorted_ranges.sort_by_key(|r| r.start);

    let mut public_ranges = Vec::new();
    let mut last_end = 0;
    for r in sorted_ranges {
        if r.start > last_end {
            public_ranges.push(last_end..r.start);
        }
        last_end = r.end;
    }

    if last_end < seq.len() {
        public_ranges.push(last_end..seq.len());
    }

    (public_ranges, private_ranges)
}

async fn build_proof_with_redactions(mut prover: Prover<Notarize>, zip_file: &[u8], query_string: &str) -> TlsProof {
    // Identify the ranges in the outbound data which contain data which we want to disclose
    let (sent_public_ranges, _) = find_ranges(
        prover.sent_transcript().data(),
        &[
            // Redact the auth part of the query string from the request. It will NOT be disclosed.
            query_string.as_bytes(),
        ],
    );

    // Extract the response headers from the raw bytes of the received transcript
    let recv_bytes = prover.recv_transcript().data();
    let headers_end = recv_bytes.windows(4).position(|window| window == b"\r\n\r\n")
        .map(|pos| pos + 4) // move past the "\r\n\r\n"
        .unwrap_or(recv_bytes.len()); // default to full length if no headers end found
    println!("headers_end: {}", headers_end);
    let recv_public_ranges = vec![0..headers_end];
    // // reveal the full response
    // // let recv_public_ranges = vec![0..recv_bytes.len()]; // didn't work
    // let (recv_public_ranges , _) = find_ranges(
    //     prover.recv_transcript().data(),
    //     &[
    //         // Redact a part of the response. It will NOT be disclosed.
    //         "user.json".as_bytes(),
    //     ],
    // );

    let builder = prover.commitment_builder();

    // Commit to each range of the public outbound data which we want to disclose
    let sent_commitments: Vec<_> = sent_public_ranges
        .iter()
        .map(|range| builder.commit_sent(range).unwrap())
        .collect();

    // Commit to each range of the public inbound data which we want to disclose
    let recv_commitments: Vec<_> = recv_public_ranges
        .iter()
        .map(|range| builder.commit_recv(range).unwrap())
        .collect();

    // Finalize, returning the notarized session
    let notarized_session = prover.finalize().await.unwrap();

    // Create a proof for all committed data in this session
    let mut proof_builder = notarized_session.data().build_substrings_proof();

    // Reveal all the public ranges
    for commitment_id in sent_commitments {
        proof_builder.reveal_by_id(commitment_id).unwrap();
    }
    for commitment_id in recv_commitments {
        proof_builder.reveal_by_id(commitment_id).unwrap();
    }

    let substrings_proof = proof_builder.build().unwrap();

    TlsProof {
        session: notarized_session.session_proof(),
        substrings: substrings_proof,
    }
}