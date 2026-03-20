// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

// F1 regression guard: ensure HTTP and TLS branches share the same request handler,
// so auth/endpoint changes can't silently diverge between transports.

#[test]
fn f1_status_serve_http_and_tls_share_one_inner_handler() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/http_api.rs");
    let src = std::fs::read_to_string(&path).expect("read phantom-node src/http_api.rs");

    assert!(
        src.contains("async fn status_serve_handle_request_inner"),
        "missing shared handler: status_serve_handle_request_inner"
    );
    assert!(
        src.contains("status_serve_handle_request_inner(peer_ip, false"),
        "missing HTTP branch call to status_serve_handle_request_inner(..., false, ...)"
    );
    assert!(
        src.contains("status_serve_handle_request_inner(peer_ip, true"),
        "missing TLS branch call to status_serve_handle_request_inner(..., true, ...)"
    );

    // One definition + 2 call sites.
    let occ = src.matches("status_serve_handle_request_inner(").count();
    assert_eq!(
        occ, 3,
        "expected exactly one shared handler definition and exactly two call sites (http+tls); got {occ}"
    );
}
