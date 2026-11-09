//! OAuth 2.1 authorization server for cloud AIs that use a person's
//! computer over MCP (docs/33 §10).
//!
//! The person's computer (the gateway) is the resource server: it serves
//! MCP, decrypts, and checks each access token here by introspection. This
//! server never sees message contents or keys. It keeps which app may use
//! which agent, and hashes of codes and tokens.
//!
//! The scope is fixed to reading and drafting (docs/33 §8): no token from
//! here lets an AI send.

use super::*;
use axum::extract::Query;
use axum::http::header;
use axum::Form;
use std::net::IpAddr;

/// Everything an AI app can be allowed to do. Sending is not among them.
const OAUTH_SCOPES: &[&str] = &["inbox.read", "inbox.draft"];
const OAUTH_CODE_TTL_SECS: i64 = 600;
const OAUTH_ACCESS_TTL_SECS: i64 = 3600;
const OAUTH_REFRESH_TTL_DAYS: i64 = 30;
/// A grant unused this long stops working (docs/33 §10, 承認: 30 日).
const OAUTH_IDLE_DAYS: i64 = 30;
const OAUTH_CLIENT_NAME_MAX: usize = 64;
const OAUTH_REDIRECT_URIS_MAX: usize = 5;
const OAUTH_REDIRECT_URI_MAX_LEN: usize = 512;
const OAUTH_REGISTER_LIMIT_PER_IP: u64 = 10;
const OAUTH_REGISTER_WINDOW_SECS: i64 = 3600;
const OAUTH_TOKEN_LIMIT_PER_IP: u64 = 60;
const OAUTH_TOKEN_WINDOW_SECS: i64 = 600;
const CLIENT_METADATA_MAX_BYTES: usize = 16 * 1024;
const CLIENT_METADATA_TTL_HOURS: i64 = 24;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn issuer(headers: &HeaderMap) -> String {
    expected_api_url(headers, "/")
        .map(|u| u.trim_end_matches('/').to_string())
        .unwrap_or_else(|| "https://api.nexusinbox.ai".to_string())
}

/// Where the consent page lives: AGENT_INBOX_WEB_URL, else the first
/// allowed browser origin.
fn web_url() -> String {
    if let Ok(raw) = std::env::var("AGENT_INBOX_WEB_URL") {
        let trimmed = raw.trim().trim_end_matches('/');
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    allowed_origins()
        .into_iter()
        .next()
        .unwrap_or_else(|| "https://app.nexusinbox.ai".to_string())
}

fn random_secret(prefix: &str) -> String {
    let mut buf = [0u8; 32];
    rand::fill(&mut buf);
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(buf))
}

fn hash_secret(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

/// An OAuth error body (RFC 6749 §5.2), with no-store.
fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

fn printable(raw: &str, max: usize) -> String {
    let mut out = String::new();
    for c in raw.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > max {
            break;
        }
        out.push(c);
    }
    out.trim().to_string()
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host == "[::1]"
}

/// A redirect URI an app may register: https, http on loopback (native
/// apps, RFC 8252 §7.3), or a private-use scheme in reverse-domain form
/// (RFC 8252 §7.1). No fragments.
fn redirect_uri_allowed(uri: &str) -> bool {
    if uri.len() > OAUTH_REDIRECT_URI_MAX_LEN || uri.contains('#') {
        return false;
    }
    let Ok(parsed) = reqwest::Url::parse(uri) else {
        return false;
    };
    match parsed.scheme() {
        "https" => parsed.host_str().is_some(),
        "http" => parsed.host_str().is_some_and(is_loopback_host),
        scheme => {
            scheme.contains('.') && !matches!(scheme, "javascript" | "data" | "file" | "vbscript")
        }
    }
}

/// Exact match, except that a loopback redirect may use any port (RFC 8252
/// §7.3), as native apps pick one at run time.
fn redirect_uri_matches(registered: &[String], requested: &str) -> bool {
    if registered.iter().any(|r| r == requested) {
        return true;
    }
    let Ok(req) = reqwest::Url::parse(requested) else {
        return false;
    };
    if req.scheme() != "http" || !req.host_str().is_some_and(is_loopback_host) {
        return false;
    }
    registered.iter().any(|r| {
        reqwest::Url::parse(r).is_ok_and(|reg| {
            reg.scheme() == "http"
                && reg.host_str() == req.host_str()
                && reg.path() == req.path()
                && reg.query() == req.query()
        })
    })
}

fn pkce_s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn valid_pkce_value(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~'))
}

/// Requested scopes, limited to what an app may have. Empty means all.
fn normalize_scope(raw: Option<&str>) -> Result<String, &'static str> {
    let requested: Vec<&str> = raw.unwrap_or("").split_whitespace().collect();
    if requested.is_empty() {
        return Ok(OAUTH_SCOPES.join(" "));
    }
    if requested.iter().any(|s| !OAUTH_SCOPES.contains(s)) {
        return Err("only inbox.read and inbox.draft can be granted");
    }
    Ok(OAUTH_SCOPES
        .iter()
        .filter(|s| requested.contains(s))
        .copied()
        .collect::<Vec<_>>()
        .join(" "))
}

async fn oauth_pool(state: &AppState) -> Result<PgPool, (StatusCode, Json<ErrorResponse>)> {
    state
        .database_pool()
        .await
        .map_err(|message| internal_server_error(&message))?
        .ok_or_else(database_required_but_unavailable_error)
}

fn rate_limited() -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(ErrorResponse {
            error: "rate_limited".into(),
            message: "too many requests from this IP; wait a few minutes".into(),
        }),
    )
}

// ---------------------------------------------------------------------------
// Metadata (RFC 8414)
// ---------------------------------------------------------------------------

/// GET /.well-known/oauth-authorization-server
pub(crate) async fn authorization_server_metadata(headers: HeaderMap) -> Response {
    let iss = issuer(&headers);
    (
        [(header::CACHE_CONTROL, "public, max-age=3600")],
        Json(serde_json::json!({
            "issuer": iss,
            "authorization_endpoint": format!("{}/oauth/authorize", web_url()),
            "token_endpoint": format!("{iss}/oauth/token"),
            "registration_endpoint": format!("{iss}/oauth/register"),
            "revocation_endpoint": format!("{iss}/oauth/revoke"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "revocation_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": OAUTH_SCOPES,
            "client_id_metadata_document_supported": true,
            "authorization_response_iss_parameter_supported": true,
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Clients: dynamic registration (RFC 7591) and metadata documents
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct RegisterClientRequest {
    client_name: Option<String>,
    redirect_uris: Option<Vec<String>>,
    token_endpoint_auth_method: Option<String>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
}

struct ClientRecord {
    client_id: String,
    client_name: String,
    redirect_uris: Vec<String>,
    kind: String,
}

fn check_client_fields(
    name: Option<&str>,
    redirect_uris: Option<&Vec<String>>,
    auth_method: Option<&str>,
    grant_types: Option<&Vec<String>>,
    response_types: Option<&Vec<String>>,
) -> Result<(String, Vec<String>), String> {
    let uris = redirect_uris
        .filter(|u| !u.is_empty() && u.len() <= OAUTH_REDIRECT_URIS_MAX)
        .ok_or("redirect_uris must hold 1 to 5 URIs")?;
    if uris.iter().any(|u| !redirect_uri_allowed(u)) {
        return Err(
            "redirect_uris must be https, http on localhost, or a private-use scheme".into(),
        );
    }
    if auth_method.is_some_and(|m| m != "none") {
        return Err("only public clients (token_endpoint_auth_method=none) are supported".into());
    }
    if grant_types.is_some_and(|g| {
        g.iter()
            .any(|t| t != "authorization_code" && t != "refresh_token")
    }) {
        return Err("grant_types may be authorization_code and refresh_token".into());
    }
    if response_types.is_some_and(|r| r.iter().any(|t| t != "code")) {
        return Err("response_types may only be code".into());
    }
    let name = printable(name.unwrap_or(""), OAUTH_CLIENT_NAME_MAX);
    let name = if name.is_empty() {
        "AI app".to_string()
    } else {
        name
    };
    Ok((name, uris.clone()))
}

/// POST /oauth/register — dynamic client registration, public clients only.
pub(crate) async fn register_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    JsonBody(payload): JsonBody<RegisterClientRequest>,
) -> Response {
    if !consume_keyed_budget(
        &state.oauth_ip_budgets,
        &format!("register:{}", extract_client_ip(&headers)),
        OAUTH_REGISTER_LIMIT_PER_IP,
        OAUTH_REGISTER_WINDOW_SECS,
    ) {
        return rate_limited().into_response();
    }
    let (name, uris) = match check_client_fields(
        payload.client_name.as_deref(),
        payload.redirect_uris.as_ref(),
        payload.token_endpoint_auth_method.as_deref(),
        payload.grant_types.as_ref(),
        payload.response_types.as_ref(),
    ) {
        Ok(v) => v,
        Err(e) => return oauth_error(StatusCode::BAD_REQUEST, "invalid_client_metadata", &e),
    };
    let pool = match oauth_pool(&state).await {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let client_id = random_secret("nxc_");
    if let Err(error) = sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, redirect_uris, kind) \
         VALUES ($1, $2, $3, 'registered')",
    )
    .bind(&client_id)
    .bind(&name)
    .bind(&uris)
    .execute(&pool)
    .await
    {
        return internal_error("failed to register client", error).into_response();
    }
    (
        StatusCode::CREATED,
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({
            "client_id": client_id,
            "client_id_issued_at": Utc::now().timestamp(),
            "client_name": name,
            "redirect_uris": uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        })),
    )
        .into_response()
}

/// True for addresses on the public internet. Anything local, private or
/// reserved is refused, so a client metadata URL cannot make this server
/// reach inside its own network.
fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || s[0] == 0x2001 && s[1] == 0x0db8
                || s[0] == 0x0064 && s[1] == 0xff9b)
        }
    }
}

/// A client metadata document URL as MCP allows it: https on port 443,
/// a host name (no IP literals, no credentials) and a path.
fn metadata_url_allowed(url: &reqwest::Url) -> bool {
    url.scheme() == "https"
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && url.path() != "/"
        && url
            .host_str()
            .is_some_and(|h| !h.starts_with('[') && h.parse::<IpAddr>().is_err())
}

/// Fetch a client metadata document, pinned to a public address.
async fn fetch_client_metadata(client_id: &str) -> Result<serde_json::Value, String> {
    let url = reqwest::Url::parse(client_id).map_err(|_| "client_id is not a URL")?;
    if !metadata_url_allowed(&url) {
        return Err("client_id URL must be https on the default port, with a path".into());
    }
    let host = url
        .host_str()
        .ok_or("client_id URL has no host")?
        .to_string();
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), 443))
        .await
        .map_err(|_| "could not resolve the client_id host")?
        .collect();
    let addr = addrs
        .first()
        .copied()
        .ok_or("could not resolve the client_id host")?;
    if addrs.iter().any(|a| !is_public_ip(a.ip())) {
        return Err("the client_id host is not on the public internet".into());
    }
    let client = reqwest::Client::builder()
        .resolve(&host, addr)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(5))
        .https_only(true)
        .build()
        .map_err(|_| "could not build an HTTP client")?;
    let mut resp = client
        .get(url)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|_| "could not fetch the client metadata")?;
    if !resp.status().is_success() {
        return Err(format!("client metadata returned {}", resp.status()));
    }
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|_| "could not read the client metadata")?
    {
        if body.len() + chunk.len() > CLIENT_METADATA_MAX_BYTES {
            return Err("client metadata is too large".into());
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| "client metadata is not JSON".into())
}

/// The app behind `client_id`: a registered one, or one known by its
/// metadata document URL (fetched again after a day).
async fn resolve_client(pool: &PgPool, client_id: &str) -> Result<ClientRecord, String> {
    let row = sqlx::query(
        "SELECT client_id, client_name, redirect_uris, kind, \
           (fetched_at > NOW() - ($2::bigint * INTERVAL '1 hour')) AS fresh \
         FROM oauth_clients WHERE client_id = $1",
    )
    .bind(client_id)
    .bind(CLIENT_METADATA_TTL_HOURS)
    .fetch_optional(pool)
    .await
    .map_err(|_| "failed to look up the client".to_string())?;
    let is_url = client_id.starts_with("https://");
    if let Some(row) = &row {
        let fresh: Option<bool> = row.get("fresh");
        if !is_url || fresh == Some(true) {
            return Ok(ClientRecord {
                client_id: row.get("client_id"),
                client_name: row.get("client_name"),
                redirect_uris: row.get("redirect_uris"),
                kind: row.get("kind"),
            });
        }
    }
    if !is_url {
        return Err("unknown client_id".into());
    }
    let doc = fetch_client_metadata(client_id).await?;
    if doc.get("client_id").and_then(|v| v.as_str()) != Some(client_id) {
        return Err("client metadata names another client_id".into());
    }
    let strings = |k: &str| -> Option<Vec<String>> {
        doc.get(k).and_then(|v| v.as_array()).map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
    };
    let (name, uris) = check_client_fields(
        doc.get("client_name").and_then(|v| v.as_str()),
        strings("redirect_uris").as_ref(),
        doc.get("token_endpoint_auth_method")
            .and_then(|v| v.as_str()),
        strings("grant_types").as_ref(),
        strings("response_types").as_ref(),
    )?;
    sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, redirect_uris, kind, fetched_at) \
         VALUES ($1, $2, $3, 'metadata_document', NOW()) \
         ON CONFLICT (client_id) DO UPDATE SET client_name = EXCLUDED.client_name, \
           redirect_uris = EXCLUDED.redirect_uris, fetched_at = NOW()",
    )
    .bind(client_id)
    .bind(&name)
    .bind(&uris)
    .execute(pool)
    .await
    .map_err(|_| "failed to save the client".to_string())?;
    Ok(ClientRecord {
        client_id: client_id.to_string(),
        client_name: name,
        redirect_uris: uris,
        kind: "metadata_document".into(),
    })
}

// ---------------------------------------------------------------------------
// MCP resources: the URL of a person's computer
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct RegisterResourceRequest {
    resource: Option<String>,
}

fn local_resources_allowed() -> bool {
    !is_production_env()
        && std::env::var("AGENT_INBOX_MCP_ALLOW_LOCAL_RESOURCES")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
}

fn resource_domain() -> String {
    std::env::var("AGENT_INBOX_MCP_RESOURCE_DOMAIN")
        .ok()
        .map(|d| d.trim().trim_matches('.').to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| "mcp.agent-inbox.ai".to_string())
}

fn new_resource_url() -> String {
    const ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyz23456789";
    let mut buf = [0u8; 10];
    rand::fill(&mut buf);
    let id: String = buf
        .iter()
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect();
    format!("https://{id}.{}/mcp", resource_domain())
}

/// POST /mcp-resources — the computer asks for (or, locally, names) its MCP
/// URL. One per credential; asking again returns the same one.
pub(crate) async fn register_mcp_resource(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    JsonBody(payload): JsonBody<RegisterResourceRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let ctx = authenticated_context(&state, &headers, method.as_str(), uri.path()).await?;
    let AuthContext::Agent {
        credential_id, aid, ..
    } = &ctx
    else {
        return Err(forbidden_error("the computer registers its MCP URL"));
    };
    ctx.require_scope("messages.read")?;
    let user_uuid = parse_user_uuid(ctx.user_id())?;
    let pool = oauth_pool(&state).await?;

    let wanted = match payload.resource.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(r) => {
            let ok = local_resources_allowed()
                && reqwest::Url::parse(r).is_ok_and(|u| {
                    matches!(u.scheme(), "http" | "https")
                        && u.host_str().is_some_and(is_loopback_host)
                        && u.query().is_none()
                        && u.fragment().is_none()
                });
            if !ok {
                return Err(validation_error(
                    "resource can only be named for a local test; leave it out",
                ));
            }
            Some(r.to_string())
        }
    };

    let existing: Option<String> =
        sqlx::query_scalar("SELECT resource FROM mcp_resources WHERE credential_id = $1")
            .bind(credential_id)
            .fetch_optional(&pool)
            .await
            .map_err(|error| internal_error("failed to look up the MCP URL", error))?;
    if let Some(existing) = existing {
        // Asking without a name keeps the assigned URL, unless it is a local
        // test URL or one from before the relay's domain (docs/33 §11.2).
        let keep = match wanted.as_deref() {
            Some(w) => w == existing,
            None => relay_hostname(&existing).is_some(),
        };
        if keep {
            return Ok(Json(serde_json::json!({ "resource": existing })));
        }
        sqlx::query("DELETE FROM mcp_resources WHERE credential_id = $1")
            .bind(credential_id)
            .execute(&pool)
            .await
            .map_err(|error| internal_error("failed to replace the MCP URL", error))?;
    }
    let local = wanted.is_some();
    let resource = wanted.unwrap_or_else(new_resource_url);
    if local {
        // Local tests reuse the same loopback URL run after run. Tokens stay
        // tied to the agent they were granted for, so moving it is safe.
        sqlx::query("DELETE FROM mcp_resources WHERE resource = $1")
            .bind(&resource)
            .execute(&pool)
            .await
            .map_err(|error| internal_error("failed to move the MCP URL", error))?;
    }
    let inserted = sqlx::query(
        "INSERT INTO mcp_resources (resource, user_id, aid, credential_id) \
         VALUES ($1, $2, $3, $4) ON CONFLICT (resource) DO NOTHING",
    )
    .bind(&resource)
    .bind(user_uuid)
    .bind(aid)
    .bind(credential_id)
    .execute(&pool)
    .await
    .map_err(|error| internal_error("failed to save the MCP URL", error))?
    .rows_affected();
    if inserted == 0 {
        return Err(conflict_error("that MCP URL is taken"));
    }
    Ok(Json(serde_json::json!({ "resource": resource })))
}

// ---------------------------------------------------------------------------
// Relay tickets (docs/33 §11.3)
// ---------------------------------------------------------------------------

const RELAY_TICKET_TTL_SECS: u64 = 120;

fn relay_host() -> String {
    std::env::var("AGENT_INBOX_RELAY_HOST")
        .ok()
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "relay.agent-inbox.ai".to_string())
}

/// The API's Ed25519 key for relay tickets: 32 bytes, base64url, in
/// `AGENT_INBOX_RELAY_TICKET_KEY`. Without it the API issues no tickets.
fn relay_ticket_key() -> Option<ed25519_dalek::SigningKey> {
    let raw = std::env::var("AGENT_INBOX_RELAY_TICKET_KEY").ok()?;
    let bytes = URL_SAFE_NO_PAD.decode(raw.trim()).ok()?;
    let seed: [u8; 32] = bytes.try_into().ok()?;
    Some(ed25519_dalek::SigningKey::from_bytes(&seed))
}

fn relay_unavailable() -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorResponse {
            error: "relay_unavailable".to_string(),
            message: "the relay is not set up on this server".to_string(),
        }),
    )
}

/// The host a relay ticket names, taken from an assigned MCP URL. Only URLs
/// under the relay's domain qualify; local test URLs never do.
fn relay_hostname(resource: &str) -> Option<String> {
    let url = reqwest::Url::parse(resource).ok()?;
    if url.scheme() != "https" || url.port().is_some() || url.path() != "/mcp" {
        return None;
    }
    let host = url.host_str()?.to_ascii_lowercase();
    let suffix = format!(".{}", resource_domain());
    let id = host.strip_suffix(&suffix)?;
    let ok = id.len() == 10
        && id
            .bytes()
            .all(|b| b"abcdefghijkmnpqrstuvwxyz23456789".contains(&b));
    ok.then_some(host)
}

fn sign_relay_ticket(key: &ed25519_dalek::SigningKey, host: &str, jkt: &str, now: u64) -> String {
    use ed25519_dalek::Signer;
    let header = serde_json::json!({ "alg": "EdDSA", "typ": "nexusinbox-relay-ticket+jwt" });
    let claims = serde_json::json!({
        "aud": relay_host(),
        "sub": host,
        "cnf": { "jkt": jkt },
        "iat": now,
        "exp": now + RELAY_TICKET_TTL_SECS,
    });
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

/// GET /mcp-relay/ticket-key — the public key the relay checks tickets
/// with. Public by design; the relay is configured with it once.
pub(crate) async fn relay_ticket_public_key(
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let key = relay_ticket_key().ok_or_else(relay_unavailable)?;
    Ok(Json(serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
    })))
}

/// POST /mcp-resources/relay-ticket — a short-lived ticket that lets this
/// computer take its own MCP host on the relay. It is bound to the DPoP key
/// of the calling token, so the relay can require proof of that key on the
/// very connection that presents it.
pub(crate) async fn relay_ticket(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let ctx = authenticated_context(&state, &headers, method.as_str(), uri.path()).await?;
    let AuthContext::Agent { credential_id, .. } = &ctx else {
        return Err(forbidden_error("the computer asks for its relay ticket"));
    };
    ctx.require_scope("messages.read")?;
    let key = relay_ticket_key().ok_or_else(relay_unavailable)?;
    let pool = oauth_pool(&state).await?;

    let token = token_from_headers(&headers);
    let jkt: Option<String> =
        sqlx::query_scalar("SELECT dpop_jkt FROM agent_tokens WHERE access_hash = $1")
            .bind(sha256_hex(token.as_bytes()))
            .fetch_optional(&pool)
            .await
            .map_err(|error| internal_error("failed to look up the token", error))?;
    let jkt = jkt
        .filter(|j| j != "none")
        .ok_or_else(|| forbidden_error("the relay needs a DPoP-bound token"))?;

    let enabled: Option<bool> = sqlx::query_scalar(
        "SELECT cloud_access_enabled_at IS NOT NULL FROM agent_credentials WHERE id = $1",
    )
    .bind(credential_id)
    .fetch_optional(&pool)
    .await
    .map_err(|error| internal_error("failed to look up cloud access", error))?;
    if enabled != Some(true) {
        return Err(forbidden_error(
            "cloud access is off for this computer; the person turns it on in the app",
        ));
    }

    let resource: Option<String> =
        sqlx::query_scalar("SELECT resource FROM mcp_resources WHERE credential_id = $1")
            .bind(credential_id)
            .fetch_optional(&pool)
            .await
            .map_err(|error| internal_error("failed to look up the MCP URL", error))?;
    let resource = resource.ok_or_else(|| not_found_error("register the MCP URL first"))?;
    let host = relay_hostname(&resource)
        .ok_or_else(|| validation_error("this MCP URL is not served through the relay"))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Ok(Json(serde_json::json!({
        "ticket": sign_relay_ticket(&key, &host, &jkt, now),
        "relay": relay_host(),
        "host": host,
        "expires_in": RELAY_TICKET_TTL_SECS,
    })))
}

/// Whether an assigned MCP URL is served through the relay.
pub(crate) fn is_relay_resource(resource: &str) -> bool {
    relay_hostname(resource).is_some()
}

#[derive(Deserialize)]
pub(crate) struct RelayStatusRequest {
    #[serde(default)]
    serving: bool,
}

/// POST /mcp-resources/relay-status — a computer set up for the relay asks
/// every 30 s whether the person has turned cloud access on, and says
/// whether it is reachable through the relay right now (docs/33 §12).
pub(crate) async fn relay_status(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    JsonBody(payload): JsonBody<RelayStatusRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let ctx = authenticated_context(&state, &headers, method.as_str(), uri.path()).await?;
    let AuthContext::Agent { credential_id, .. } = &ctx else {
        return Err(forbidden_error("the computer reports its relay status"));
    };
    ctx.require_scope("messages.read")?;
    let pool = oauth_pool(&state).await?;
    let enabled: Option<bool> = sqlx::query_scalar(
        "UPDATE agent_credentials SET cloud_serving_at = \
           CASE WHEN $2 AND cloud_access_enabled_at IS NOT NULL THEN NOW() ELSE NULL END \
         WHERE id = $1 RETURNING cloud_access_enabled_at IS NOT NULL",
    )
    .bind(credential_id)
    .bind(payload.serving)
    .fetch_optional(&pool)
    .await
    .map_err(|error| internal_error("failed to update the relay status", error))?;
    let enabled = enabled == Some(true) && relay_ticket_key().is_some();
    Ok(Json(serde_json::json!({ "enabled": enabled })))
}

#[derive(Deserialize)]
pub(crate) struct CloudAccessRequest {
    enabled: bool,
}

/// PUT /agent-credentials/:id/cloud-access — the person lets cloud AIs reach
/// this computer through the relay, or stops it. Stopping also disconnects
/// every AI app that was allowed in through this computer (docs/33 §12).
pub(crate) async fn set_cloud_access(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    JsonBody(payload): JsonBody<CloudAccessRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let user_uuid = parse_user_uuid(&user_id)?;
    let pool = oauth_pool(&state).await?;
    if payload.enabled && relay_ticket_key().is_none() {
        return Err(relay_unavailable());
    }
    let aid: String = sqlx::query_scalar(
        "UPDATE agent_credentials SET \
           cloud_access_enabled_at = CASE WHEN $3 THEN COALESCE(cloud_access_enabled_at, NOW()) ELSE NULL END, \
           cloud_serving_at = CASE WHEN $3 THEN cloud_serving_at ELSE NULL END \
         WHERE id = $1 AND user_id = $2 AND status = 'active' AND key_holder = 'signer_daemon' \
         RETURNING aid",
    )
    .bind(id)
    .bind(user_uuid)
    .bind(payload.enabled)
    .fetch_optional(&pool)
    .await
    .map_err(|error| internal_error("failed to update cloud access", error))?
    .ok_or_else(|| not_found_error("no active computer with that id"))?;
    let mut disconnected = 0;
    if !payload.enabled {
        disconnected = sqlx::query(
            "UPDATE oauth_grants SET revoked_at = NOW() \
             WHERE user_id = $1 AND revoked_at IS NULL \
               AND resource IN (SELECT resource FROM mcp_resources WHERE credential_id = $2)",
        )
        .bind(user_uuid)
        .bind(id)
        .execute(&pool)
        .await
        .map_err(|error| internal_error("failed to disconnect AI apps", error))?
        .rows_affected();
    }
    record_audit_event(
        pool,
        user_uuid,
        Some(id),
        Some(aid),
        if payload.enabled {
            "cloud_access_enabled"
        } else {
            "cloud_access_disabled"
        },
        serde_json::json!({ "disconnected": disconnected }),
    );
    Ok(Json(serde_json::json!({
        "cloud_access": payload.enabled,
        "disconnected": disconnected,
    })))
}

// ---------------------------------------------------------------------------
// Authorization (the consent page calls these with the person's session)
// ---------------------------------------------------------------------------

#[derive(Deserialize, Clone)]
pub(crate) struct AuthorizeParams {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    scope: Option<String>,
    resource: Option<String>,
}

struct CheckedRequest {
    client: ClientRecord,
    redirect_uri: String,
    code_challenge: String,
    scope: String,
    resource: String,
    aid: String,
    agent_label: String,
    device_label: Option<String>,
}

/// Validate an authorization request for the signed-in person. Errors are
/// shown on the consent page, never sent to the redirect URI.
async fn check_authorize(
    pool: &PgPool,
    user_uuid: Uuid,
    p: &AuthorizeParams,
) -> Result<CheckedRequest, String> {
    if p.response_type.as_deref() != Some("code") {
        return Err("response_type must be code".into());
    }
    let client_id = p.client_id.as_deref().ok_or("client_id is missing")?;
    let client = resolve_client(pool, client_id).await?;
    let redirect_uri = p.redirect_uri.clone().ok_or("redirect_uri is missing")?;
    if !redirect_uri_matches(&client.redirect_uris, &redirect_uri) {
        return Err("redirect_uri is not registered for this app".into());
    }
    if p.code_challenge_method.as_deref() != Some("S256") {
        return Err("PKCE with S256 is required".into());
    }
    let code_challenge = p
        .code_challenge
        .clone()
        .filter(|c| valid_pkce_value(c))
        .ok_or("code_challenge is missing or malformed")?;
    if p.state.as_deref().is_some_and(|s| s.len() > 512) {
        return Err("state is too long".into());
    }
    let scope = normalize_scope(p.scope.as_deref())?;
    let resource = p
        .resource
        .clone()
        .ok_or("resource is missing: the app must say which MCP server it is for")?;
    let row = sqlx::query(
        r#"
        SELECT r.aid, a.label, c.label AS device_label
        FROM mcp_resources r
        JOIN agent_identities i ON i.aid = r.aid
        JOIN agents a ON a.id = i.agent_id
        LEFT JOIN agent_credentials c ON c.id = r.credential_id
        WHERE r.resource = $1 AND r.user_id = $2
        "#,
    )
    .bind(&resource)
    .bind(user_uuid)
    .fetch_optional(pool)
    .await
    .map_err(|_| "failed to look up the MCP URL".to_string())?
    .ok_or("this MCP URL is not one of your computers")?;
    Ok(CheckedRequest {
        client,
        redirect_uri,
        code_challenge,
        scope,
        resource,
        aid: row.get("aid"),
        agent_label: row.get("label"),
        device_label: row.get("device_label"),
    })
}

fn with_query(base: &str, pairs: &[(&str, &str)]) -> String {
    let mut url = match reqwest::Url::parse(base) {
        Ok(u) => u,
        Err(_) => return base.to_string(),
    };
    {
        let mut q = url.query_pairs_mut();
        for (k, v) in pairs {
            q.append_pair(k, v);
        }
    }
    url.to_string()
}

/// GET /oauth/authorize/info — what the consent page shows.
pub(crate) async fn authorize_info(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<AuthorizeParams>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let user_uuid = parse_user_uuid(&user_id)?;
    let pool = oauth_pool(&state).await?;
    let checked = check_authorize(&pool, user_uuid, &params)
        .await
        .map_err(|e| validation_error(&e))?;
    let redirect_host = reqwest::Url::parse(&checked.redirect_uri)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_default();
    Ok(Json(serde_json::json!({
        "client_name": checked.client.client_name,
        "client_id": checked.client.client_id,
        "client_kind": checked.client.kind,
        "redirect_host": redirect_host,
        "agent_label": checked.agent_label,
        "device_label": checked.device_label,
        "aid": checked.aid,
        "scope": checked.scope.split(' ').collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
pub(crate) struct AuthorizeDecision {
    #[serde(flatten)]
    params: AuthorizeParams,
    approve: bool,
}

/// POST /oauth/authorize — the person allows or declines. Returns where the
/// browser goes next (the app's redirect URI with a code or an error).
pub(crate) async fn authorize_decide(
    State(state): State<AppState>,
    headers: HeaderMap,
    JsonBody(decision): JsonBody<AuthorizeDecision>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let user_uuid = parse_user_uuid(&user_id)?;
    let pool = oauth_pool(&state).await?;
    let checked = check_authorize(&pool, user_uuid, &decision.params)
        .await
        .map_err(|e| validation_error(&e))?;
    let iss = issuer(&headers);
    let state_param = decision.params.state.clone().unwrap_or_default();
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    if !state_param.is_empty() {
        pairs.push(("state", &state_param));
    }
    pairs.push(("iss", &iss));

    if !decision.approve {
        let mut denied = vec![("error", "access_denied")];
        denied.extend(pairs.iter().copied());
        return Ok(Json(serde_json::json!({
            "redirect_to": with_query(&checked.redirect_uri, &denied),
        })));
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(|error| internal_error("failed to start", error))?;
    // One live grant per app and computer: a new consent replaces the old.
    sqlx::query(
        "UPDATE oauth_grants SET revoked_at = NOW() \
         WHERE user_id = $1 AND client_id = $2 AND resource = $3 AND revoked_at IS NULL",
    )
    .bind(user_uuid)
    .bind(&checked.client.client_id)
    .bind(&checked.resource)
    .execute(&mut *tx)
    .await
    .map_err(|error| internal_error("failed to replace the grant", error))?;
    let grant_id: Uuid = sqlx::query_scalar(
        "INSERT INTO oauth_grants (user_id, client_id, aid, resource, scope) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(user_uuid)
    .bind(&checked.client.client_id)
    .bind(&checked.aid)
    .bind(&checked.resource)
    .bind(&checked.scope)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| internal_error("failed to save the grant", error))?;
    let code = random_secret("");
    sqlx::query(
        "INSERT INTO oauth_codes (code_hash, grant_id, redirect_uri, code_challenge, expires_at) \
         VALUES ($1, $2, $3, $4, NOW() + ($5::bigint * INTERVAL '1 second'))",
    )
    .bind(hash_secret(&code))
    .bind(grant_id)
    .bind(&checked.redirect_uri)
    .bind(&checked.code_challenge)
    .bind(OAUTH_CODE_TTL_SECS)
    .execute(&mut *tx)
    .await
    .map_err(|error| internal_error("failed to save the code", error))?;
    tx.commit()
        .await
        .map_err(|error| internal_error("failed to save", error))?;

    record_audit_event(
        pool,
        user_uuid,
        None,
        Some(checked.aid.clone()),
        "oauth_grant_created",
        serde_json::json!({
            "grant_id": grant_id,
            "client_name": checked.client.client_name,
            "scope": checked.scope,
        }),
    );
    let mut granted = vec![("code", code.as_str())];
    granted.extend(pairs.iter().copied());
    Ok(Json(serde_json::json!({
        "redirect_to": with_query(&checked.redirect_uri, &granted),
    })))
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct TokenRequest {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    resource: Option<String>,
}

async fn issue_tokens(pool: &PgPool, grant_id: Uuid, scope: &str) -> Response {
    let access = random_secret("nxa_");
    let refresh = random_secret("nxr_");
    let inserted = sqlx::query(
        "INSERT INTO oauth_tokens \
           (grant_id, access_hash, refresh_hash, access_expires_at, refresh_expires_at) \
         VALUES ($1, $2, $3, NOW() + ($4::bigint * INTERVAL '1 second'), \
                 NOW() + ($5::bigint * INTERVAL '1 day'))",
    )
    .bind(grant_id)
    .bind(hash_secret(&access))
    .bind(hash_secret(&refresh))
    .bind(OAUTH_ACCESS_TTL_SECS)
    .bind(OAUTH_REFRESH_TTL_DAYS)
    .execute(pool)
    .await;
    if let Err(error) = inserted {
        return internal_error("failed to issue tokens", error).into_response();
    }
    let _ = sqlx::query("UPDATE oauth_grants SET last_used_at = NOW() WHERE id = $1")
        .bind(grant_id)
        .execute(pool)
        .await;
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(serde_json::json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": OAUTH_ACCESS_TTL_SECS,
            "refresh_token": refresh,
            "scope": scope,
        })),
    )
        .into_response()
}

async fn revoke_grant(pool: &PgPool, grant_id: Uuid) {
    let _ = sqlx::query(
        "UPDATE oauth_grants SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(grant_id)
    .execute(pool)
    .await;
}

/// POST /oauth/token — authorization_code (with PKCE) and refresh_token.
pub(crate) async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<TokenRequest>,
) -> Response {
    if !consume_keyed_budget(
        &state.oauth_ip_budgets,
        &format!("token:{}", extract_client_ip(&headers)),
        OAUTH_TOKEN_LIMIT_PER_IP,
        OAUTH_TOKEN_WINDOW_SECS,
    ) {
        return rate_limited().into_response();
    }
    let pool = match oauth_pool(&state).await {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };
    let client_id = req.client_id.clone().unwrap_or_default();
    let bad_grant = |msg: &str| oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", msg);

    match req.grant_type.as_deref() {
        Some("authorization_code") => {
            let (Some(code), Some(redirect_uri), Some(verifier)) =
                (&req.code, &req.redirect_uri, &req.code_verifier)
            else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "code, redirect_uri and code_verifier are required",
                );
            };
            // Mark the code used first, so it works once.
            let row = match sqlx::query(
                r#"
                UPDATE oauth_codes SET used_at = NOW()
                WHERE code_hash = $1 AND used_at IS NULL
                RETURNING grant_id, redirect_uri, code_challenge, expires_at > NOW() AS live
                "#,
            )
            .bind(hash_secret(code))
            .fetch_optional(&pool)
            .await
            {
                Ok(r) => r,
                Err(error) => {
                    return internal_error("failed to redeem the code", error).into_response()
                }
            };
            let Some(row) = row else {
                // A second use of a code means it leaked: stop its grant.
                if let Ok(Some(grant_id)) = sqlx::query_scalar::<_, Uuid>(
                    "SELECT grant_id FROM oauth_codes WHERE code_hash = $1",
                )
                .bind(hash_secret(code))
                .fetch_optional(&pool)
                .await
                {
                    revoke_grant(&pool, grant_id).await;
                }
                return bad_grant("the code is unknown or was already used");
            };
            let grant_id: Uuid = row.get("grant_id");
            let live: bool = row.get("live");
            let stored_redirect: String = row.get("redirect_uri");
            let challenge: String = row.get("code_challenge");
            if !live {
                return bad_grant("the code has expired");
            }
            if &stored_redirect != redirect_uri {
                return bad_grant("redirect_uri does not match");
            }
            if !valid_pkce_value(verifier) || pkce_s256(verifier) != challenge {
                return bad_grant("code_verifier does not match");
            }
            let grant = match sqlx::query(
                "SELECT client_id, resource, scope, revoked_at IS NULL AS active \
                 FROM oauth_grants WHERE id = $1",
            )
            .bind(grant_id)
            .fetch_one(&pool)
            .await
            {
                Ok(g) => g,
                Err(error) => {
                    return internal_error("failed to load the grant", error).into_response()
                }
            };
            let grant_client: String = grant.get("client_id");
            let resource: String = grant.get("resource");
            if grant_client != client_id {
                return bad_grant("the code was issued to another client");
            }
            if req.resource.as_deref().is_some_and(|r| r != resource) {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_target",
                    "resource does not match the grant",
                );
            }
            if !grant.get::<bool, _>("active") {
                return bad_grant("the grant was revoked");
            }
            let scope: String = grant.get("scope");
            issue_tokens(&pool, grant_id, &scope).await
        }
        Some("refresh_token") => {
            let Some(refresh) = &req.refresh_token else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "refresh_token is required",
                );
            };
            let row = match sqlx::query(
                r#"
                SELECT t.id, t.grant_id, t.rotated_at IS NOT NULL AS rotated,
                       t.refresh_expires_at > NOW() AS live,
                       g.client_id, g.resource, g.scope,
                       (g.revoked_at IS NULL
                        AND g.last_used_at > NOW() - ($2::bigint * INTERVAL '1 day')) AS active
                FROM oauth_tokens t JOIN oauth_grants g ON g.id = t.grant_id
                WHERE t.refresh_hash = $1
                "#,
            )
            .bind(hash_secret(refresh))
            .bind(OAUTH_IDLE_DAYS)
            .fetch_optional(&pool)
            .await
            {
                Ok(r) => r,
                Err(error) => {
                    return internal_error("failed to look up the token", error).into_response()
                }
            };
            let Some(row) = row else {
                return bad_grant("unknown refresh_token");
            };
            let grant_id: Uuid = row.get("grant_id");
            if row.get::<bool, _>("rotated") {
                // An old refresh token came back: someone else has a copy.
                revoke_grant(&pool, grant_id).await;
                return bad_grant("refresh_token was already used; the connection was stopped");
            }
            if row.get::<String, _>("client_id") != client_id {
                return bad_grant("refresh_token was issued to another client");
            }
            if req
                .resource
                .as_deref()
                .is_some_and(|r| r != row.get::<String, _>("resource"))
            {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_target",
                    "resource does not match the grant",
                );
            }
            if !row.get::<bool, _>("live") || !row.get::<bool, _>("active") {
                return bad_grant("the connection has ended; connect again");
            }
            let token_id: Uuid = row.get("id");
            let rotated = sqlx::query(
                "UPDATE oauth_tokens SET rotated_at = NOW() WHERE id = $1 AND rotated_at IS NULL",
            )
            .bind(token_id)
            .execute(&pool)
            .await
            .map(|r| r.rows_affected())
            .unwrap_or(0);
            if rotated == 0 {
                revoke_grant(&pool, grant_id).await;
                return bad_grant("refresh_token was already used; the connection was stopped");
            }
            let scope: String = row.get("scope");
            issue_tokens(&pool, grant_id, &scope).await
        }
        _ => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "grant_type must be authorization_code or refresh_token",
        ),
    }
}

#[derive(Deserialize)]
pub(crate) struct RevokeRequest {
    token: Option<String>,
    client_id: Option<String>,
}

/// POST /oauth/revoke (RFC 7009) — an app ends its own connection.
pub(crate) async fn revoke(
    State(state): State<AppState>,
    Form(req): Form<RevokeRequest>,
) -> Response {
    let Ok(pool) = oauth_pool(&state).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if let Some(token) = req.token.as_deref() {
        let h = hash_secret(token);
        if let Ok(Some(row)) = sqlx::query(
            "SELECT t.grant_id, g.client_id FROM oauth_tokens t \
             JOIN oauth_grants g ON g.id = t.grant_id \
             WHERE t.access_hash = $1 OR t.refresh_hash = $1",
        )
        .bind(&h)
        .fetch_optional(&pool)
        .await
        {
            if req.client_id.as_deref() == Some(row.get::<String, _>("client_id").as_str()) {
                revoke_grant(&pool, row.get("grant_id")).await;
            }
        }
    }
    // Always 200, whether or not the token was known.
    StatusCode::OK.into_response()
}

#[derive(Deserialize)]
pub(crate) struct IntrospectRequest {
    token: String,
}

/// POST /oauth/introspect — the computer checks a token it was given. Only
/// tokens for the caller's own agent are reported active.
pub(crate) async fn introspect(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    JsonBody(req): JsonBody<IntrospectRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let ctx = authenticated_context(&state, &headers, method.as_str(), uri.path()).await?;
    let AuthContext::Agent { aid, .. } = &ctx else {
        return Err(forbidden_error("only the computer checks tokens"));
    };
    let pool = oauth_pool(&state).await?;
    let row = sqlx::query(
        r#"
        SELECT g.id AS grant_id, g.aid, g.resource, g.scope, g.client_id, c.client_name,
               EXTRACT(EPOCH FROM t.access_expires_at)::bigint AS exp,
               g.last_used_at < NOW() - INTERVAL '5 minutes' AS stale
        FROM oauth_tokens t
        JOIN oauth_grants g ON g.id = t.grant_id
        JOIN oauth_clients c ON c.client_id = g.client_id
        WHERE t.access_hash = $1
          AND t.access_expires_at > NOW()
          AND g.revoked_at IS NULL
          AND g.last_used_at > NOW() - ($2::bigint * INTERVAL '1 day')
        "#,
    )
    .bind(hash_secret(req.token.trim()))
    .bind(OAUTH_IDLE_DAYS)
    .fetch_optional(&pool)
    .await
    .map_err(|error| internal_error("failed to check the token", error))?;
    let Some(row) = row.filter(|r| r.get::<String, _>("aid") == *aid) else {
        return Ok(Json(serde_json::json!({ "active": false })));
    };
    let grant_id: Uuid = row.get("grant_id");
    if row.get::<bool, _>("stale") {
        let _ = sqlx::query("UPDATE oauth_grants SET last_used_at = NOW() WHERE id = $1")
            .bind(grant_id)
            .execute(&pool)
            .await;
    }
    Ok(Json(serde_json::json!({
        "active": true,
        "scope": row.get::<String, _>("scope"),
        "client_id": row.get::<String, _>("client_id"),
        "client_name": row.get::<String, _>("client_name"),
        "aid": row.get::<String, _>("aid"),
        "aud": row.get::<String, _>("resource"),
        "exp": row.get::<i64, _>("exp"),
        "grant_id": grant_id,
    })))
}

// ---------------------------------------------------------------------------
// The person's list of connected AIs
// ---------------------------------------------------------------------------

/// GET /oauth/grants — AI apps connected to the person's agents.
pub(crate) async fn list_grants(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let user_uuid = parse_user_uuid(&user_id)?;
    let pool = oauth_pool(&state).await?;
    let rows = sqlx::query(
        r#"
        SELECT g.id, g.aid, g.resource, g.scope, g.created_at::text AS created_at,
               g.last_used_at::text AS last_used_at, c.client_name, a.label AS agent_label
        FROM oauth_grants g
        JOIN oauth_clients c ON c.client_id = g.client_id
        JOIN agent_identities i ON i.aid = g.aid
        JOIN agents a ON a.id = i.agent_id
        WHERE g.user_id = $1 AND g.revoked_at IS NULL
          AND g.last_used_at > NOW() - ($2::bigint * INTERVAL '1 day')
        ORDER BY g.last_used_at DESC
        "#,
    )
    .bind(user_uuid)
    .bind(OAUTH_IDLE_DAYS)
    .fetch_all(&pool)
    .await
    .map_err(|error| internal_error("failed to list connections", error))?;
    let grants: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "id": r.get::<Uuid, _>("id"),
                "aid": r.get::<String, _>("aid"),
                "resource": r.get::<String, _>("resource"),
                "agent_label": r.get::<String, _>("agent_label"),
                "client_name": r.get::<String, _>("client_name"),
                "scope": r.get::<String, _>("scope").split(' ').collect::<Vec<_>>(),
                "created_at": r.get::<String, _>("created_at"),
                "last_used_at": r.get::<String, _>("last_used_at"),
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "grants": grants })))
}

/// DELETE /oauth/grants/:id — the person disconnects an AI app.
pub(crate) async fn delete_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let user_uuid = parse_user_uuid(&user_id)?;
    let pool = oauth_pool(&state).await?;
    let row = sqlx::query(
        "UPDATE oauth_grants g SET revoked_at = NOW() FROM oauth_clients c \
         WHERE g.id = $1 AND g.user_id = $2 AND g.revoked_at IS NULL \
           AND c.client_id = g.client_id \
         RETURNING g.aid, c.client_name",
    )
    .bind(id)
    .bind(user_uuid)
    .fetch_optional(&pool)
    .await
    .map_err(|error| internal_error("failed to disconnect", error))?
    .ok_or_else(|| not_found_error("connection not found"))?;
    record_audit_event(
        pool,
        user_uuid,
        None,
        Some(row.get("aid")),
        "oauth_grant_revoked",
        serde_json::json!({ "grant_id": id, "client_name": row.get::<String, _>("client_name") }),
    );
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uris_are_limited() {
        assert!(redirect_uri_allowed(
            "https://claude.ai/api/mcp/auth_callback"
        ));
        assert!(redirect_uri_allowed("http://127.0.0.1:33418/callback"));
        assert!(redirect_uri_allowed("http://localhost/cb"));
        assert!(redirect_uri_allowed("com.example.app:/oauth"));
        assert!(!redirect_uri_allowed("http://evil.example/cb"));
        assert!(!redirect_uri_allowed("javascript:alert(1)"));
        assert!(!redirect_uri_allowed("https://a.example/cb#frag"));
        assert!(!redirect_uri_allowed("myapp:/cb"));
    }

    #[test]
    fn loopback_redirects_may_change_port_only() {
        let reg = vec!["http://127.0.0.1/callback".to_string()];
        assert!(redirect_uri_matches(&reg, "http://127.0.0.1:5555/callback"));
        assert!(!redirect_uri_matches(&reg, "http://127.0.0.1:5555/other"));
        let reg = vec!["https://app.example/cb".to_string()];
        assert!(redirect_uri_matches(&reg, "https://app.example/cb"));
        assert!(!redirect_uri_matches(&reg, "https://app.example/cb?x=1"));
    }

    #[test]
    fn scope_never_includes_sending() {
        assert_eq!(normalize_scope(None).unwrap(), "inbox.read inbox.draft");
        assert_eq!(normalize_scope(Some("inbox.read")).unwrap(), "inbox.read");
        assert!(normalize_scope(Some("inbox.send")).is_err());
        assert!(normalize_scope(Some("messages.send inbox.read")).is_err());
    }

    #[test]
    fn pkce_matches_rfc_7636_example() {
        assert_eq!(
            pkce_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn private_addresses_are_refused() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!is_public_ip(ip.parse().unwrap()), "{ip}");
        }
        assert!(is_public_ip("1.1.1.1".parse().unwrap()));
        assert!(is_public_ip("2606:4700::1111".parse().unwrap()));
    }

    #[test]
    fn metadata_urls_are_limited() {
        let ok = |s: &str| metadata_url_allowed(&reqwest::Url::parse(s).unwrap());
        assert!(ok("https://app.example/oauth/client.json"));
        assert!(!ok("http://app.example/client.json"));
        assert!(!ok("https://app.example:8443/client.json"));
        assert!(!ok("https://10.0.0.1/client.json"));
        assert!(!ok("https://app.example/"));
        assert!(!ok("https://user@app.example/c.json"));
    }
}
