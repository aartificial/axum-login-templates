use crate::routes::error::AppError;
use crate::routes::UserData;
use axum::extract::{Host, Query, State};
use axum::headers::{Cookie, HeaderName};
use axum::response::{AppendHeaders, IntoResponse, Redirect};
use axum::{Extension, TypedHeader};
use chrono::Utc;
use dotenv::var;
use oauth2::basic::BasicClient;
use oauth2::basic::BasicTokenResponse;
use oauth2::reqwest::http_client;
use oauth2::url::Url;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, RevocationUrl, Scope, TokenResponse, TokenUrl,
};
use sqlx::{Error, PgPool};
use std::collections::HashMap;
use std::string::ToString;
use uuid::Uuid;

const LOGOUT_COOKIE: &str =
    "session_token=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; secure; httponly";
const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://www.googleapis.com/oauth2/v3/token";
const REVOCATION_URL: &str = "https://oauth2.googleapis.com/revoke";
const USERINFO_EMAIL_URL: &str = "https://www.googleapis.com/auth/userinfo.email";

pub async fn login(
    Extension(user_data): Extension<Option<UserData>>,
    Query(mut params): Query<HashMap<String, String>>,
    State(db_pool): State<PgPool>,
    Host(hostname): Host,
) -> Result<Redirect, AppError> {
    if user_data.is_some() {
        return Ok(Redirect::to("/"));
    }

    let return_url = params
        .remove("return_url")
        .unwrap_or_else(|| "/".to_owned());

    let (pkce_code_verifier, authorize_url, csrf_state) = authorize(hostname)?;
    add_oauth2_state_storage(&db_pool, return_url, pkce_code_verifier, csrf_state).await?;

    Ok(Redirect::to(authorize_url.as_str()))
}

pub async fn logout(
    cookie: Option<TypedHeader<Cookie>>,
    State(db_pool): State<PgPool>,
) -> Result<impl IntoResponse, AppError> {
    let session_token = parse_session_token(cookie).await?;
    delete_user_session(&db_pool, &session_token).await?;
    let headers = AppendHeaders([(axum::http::header::SET_COOKIE, LOGOUT_COOKIE)]);
    Ok((headers, Redirect::to("/")))
}

pub async fn oauth_return(
    Query(mut params): Query<HashMap<String, String>>,
    State(db_pool): State<PgPool>,
    Host(hostname): Host,
) -> Result<impl IntoResponse, AppError> {
    let state = CsrfToken::new(params.remove("state").ok_or("OAuth: without state")?);
    let code = AuthorizationCode::new(params.remove("code").ok_or("OAuth: without code")?);

    let (pkce_code_verifier, return_url) = delete_oauth2_state_storage(&db_pool, state).await?;
    let pkce_code_verifier = PkceCodeVerifier::new(pkce_code_verifier);

    let client = get_client(hostname)?;
    let token_response = handle_token(client, code, pkce_code_verifier).await?;
    let access_token = token_response.access_token().secret();
    let email = parse_url(access_token).await?;

    let user_id = match get_user_id(&db_pool, &email).await {
        Ok((id,)) => id,
        Err(_) => create_user(&db_pool, email).await?,
    };

    let (session_token_p1, session_token_p2, headers, now) = set_session();
    create_user_session(&db_pool, user_id, session_token_p1, session_token_p2, now).await?;

    Ok((headers, Redirect::to(return_url.as_str())))
}

fn set_session() -> (
    String,
    String,
    AppendHeaders<[(HeaderName, String); 1]>,
    i64,
) {
    let session_token_p1 = Uuid::new_v4().to_string();
    let session_token_p2 = Uuid::new_v4().to_string();
    let session_token = [session_token_p1.as_str(), "_", session_token_p2.as_str()].concat();
    let headers = AppendHeaders([(
        axum::http::header::SET_COOKIE,
        "session_token=".to_owned()
            + &*session_token
            + "; path=/; httponly; secure; samesite=strict",
    )]);
    let now = Utc::now().timestamp();
    (session_token_p1, session_token_p2, headers, now)
}

fn authorize(hostname: String) -> Result<(PkceCodeVerifier, Url, CsrfToken), AppError> {
    let client = get_client(hostname)?;

    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    let (authorize_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new(USERINFO_EMAIL_URL.to_string()))
        .set_pkce_challenge(pkce_code_challenge)
        .url();

    Ok((pkce_code_verifier, authorize_url, csrf_state))
}

fn get_client(hostname: String) -> Result<BasicClient, AppError> {
    let google_client_id = ClientId::new(var("GOOGLE_CLIENT_ID")?);
    let google_client_secret = ClientSecret::new(var("GOOGLE_CLIENT_SECRET")?);

    let auth_url = AuthUrl::new(AUTH_URL.to_string())
        .map_err(|_| "OAuth: invalid authorization endpoint URL")?;
    let token_url =
        TokenUrl::new(TOKEN_URL.to_string()).map_err(|_| "OAuth: invalid token endpoint URL")?;

    let protocol = if var("USE_HTTP").ok().map_or(false, |v| v == "true") {
        "http"
    } else {
        "https"
    };
    let redirect_url = format!("{}://{}/oauth_return", protocol, hostname);
    let redirect_url = RedirectUrl::new(redirect_url).map_err(|_| "OAuth: invalid redirect URL")?;
    let revocation_url = RevocationUrl::new(REVOCATION_URL.to_string())
        .map_err(|_| "OAuth: invalid revocation URL")?;

    let client = BasicClient::new(
        google_client_id,
        Some(google_client_secret),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(redirect_url)
    .set_revocation_uri(revocation_url);

    Ok(client)
}

async fn handle_token(
    client: BasicClient,
    code: AuthorizationCode,
    pkce_code_verifier: PkceCodeVerifier,
) -> Result<BasicTokenResponse, &'static str> {
    tokio::task::spawn_blocking(move || {
        client
            .exchange_code(code)
            .set_pkce_verifier(pkce_code_verifier)
            .request(http_client)
    })
    .await
    .map_err(|_| "OAuth: exchange_code failure")?
    .map_err(|_| "OAuth: spawn_blocking failure")
}

async fn add_oauth2_state_storage(
    db_pool: &PgPool,
    return_url: String,
    pkce_code_verifier: PkceCodeVerifier,
    csrf_state: CsrfToken,
) -> Result<(), AppError> {
    sqlx::query(
        r#"
        INSERT INTO oauth2_state_storage 
        (csrf_state, pkce_code_verifier, return_url) 
        VALUES 
        ($1, $2, $3);
        "#,
    )
    .bind(csrf_state.secret())
    .bind(pkce_code_verifier.secret())
    .bind(return_url)
    .execute(db_pool)
    .await?;
    Ok(())
}

async fn create_user_session(
    db_pool: &PgPool,
    user_id: i64,
    session_token_p1: String,
    session_token_p2: String,
    now: i64,
) -> Result<(), AppError> {
    sqlx::query(
        r#"
        INSERT INTO user_sessions
        (session_token_p1, session_token_p2, user_id, created_at, expires_at)
        VALUES ($1, $2, $3, $4, $5);
        "#,
    )
    .bind(session_token_p1)
    .bind(session_token_p2)
    .bind(user_id)
    .bind(now)
    .bind(now + 60 * 60 * 24)
    .execute(db_pool)
    .await?;
    Ok(())
}

async fn create_user(db_pool: &PgPool, email: String) -> Result<i64, AppError> {
    let (id,): (i64,) = sqlx::query_as(
        r#"
            INSERT INTO users 
            (email) 
            VALUES 
            ($1) 
            RETURNING id
        "#,
    )
    .bind(email)
    .fetch_one(db_pool)
    .await?;
    Ok(id)
}

async fn get_user_id(db_pool: &PgPool, email: &String) -> Result<(i64,), Error> {
    let query: Result<(i64,), _> = sqlx::query_as(
        r#"
        SELECT id 
        FROM users 
        WHERE email=$1
    "#,
    )
    .bind(email.as_str())
    .fetch_one(db_pool)
    .await;
    query
}
async fn delete_oauth2_state_storage(
    db_pool: &PgPool,
    state: CsrfToken,
) -> Result<(String, String), AppError> {
    let query: (String, String) = sqlx::query_as(
        r#"
        DELETE 
        FROM oauth2_state_storage 
        WHERE csrf_state = $1 
        RETURNING pkce_code_verifier,return_url
        "#,
    )
    .bind(state.secret())
    .fetch_one(db_pool)
    .await?;
    Ok(query)
}
async fn delete_user_session(db_pool: &PgPool, token: &str) -> Result<u64, AppError> {
    let rows_affected = sqlx::query(
        r#"
        DELETE 
        FROM user_sessions 
        WHERE session_token_p1 = $1
        "#,
    )
    .bind(token)
    .execute(db_pool)
    .await?
    .rows_affected();
    if rows_affected == 0 {
        return Err(AppError::new("Session not found."));
    }
    Ok(rows_affected)
}
async fn parse_session_token(cookie: Option<TypedHeader<Cookie>>) -> Result<String, AppError> {
    let cookie = cookie.ok_or(AppError::new("No cookie provided."))?;
    let session_token = cookie
        .get("session_token")
        .ok_or(AppError::new("Missing session token."))?
        .split('_')
        .collect::<Vec<&str>>();
    if session_token.len() < 2 {
        return Err(AppError::new("Invalid session token format."));
    }
    Ok(session_token[0].to_string())
}
async fn parse_url(access_token: &String) -> Result<String, AppError> {
    let url =
        "https://www.googleapis.com/oauth2/v2/userinfo?oauth_token=".to_owned() + access_token;
    let body = reqwest::get(url)
        .await
        .map_err(|_| "OAuth: reqwest failed to query userinfo")?
        .text()
        .await
        .map_err(|_| "OAuth: reqwest received invalid userinfo")?;
    let mut body: serde_json::Value =
        serde_json::from_str(body.as_str()).map_err(|_| "OAuth: Serde failed to parse userinfo")?;
    let email = body["email"]
        .take()
        .as_str()
        .ok_or("OAuth: Serde failed to parse email address")?
        .to_owned();
    let verified_email = body["verified_email"]
        .take()
        .as_bool()
        .ok_or("OAuth: Serde failed to parse verified_email")?;
    if !verified_email {
        return Err(AppError::new("OAuth: email address is not verified".to_owned())
            .with_user_message("Your email address is not verified. Please verify your email address with Google and try again.".to_owned()));
    }
    Ok(email)
}
