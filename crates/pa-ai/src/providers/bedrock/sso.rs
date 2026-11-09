//! AWS IAM Identity Center (SSO) profiles: a profile naming `sso_account_id` and `sso_role_name`,
//! with `sso_start_url` / `sso_region` inline (legacy form) or in its `[sso-session <name>]`
//! section. The access token `aws sso login` cached under `~/.aws/sso/cache` is exchanged at the
//! SSO portal for role credentials, cached until shortly before they expire. The token itself is
//! never refreshed here: once it lapses, `aws sso login` issues a new one.

use std::collections::HashMap;
use std::path::Path;

use serde_json::Value;
use sha1::{Digest, Sha1};

use crate::providers::bedrock::auth::{profile_section_matches, AwsCredentials};
use crate::providers::bedrock::credential_process::{
    cache_credentials, cached_credentials, parse_rfc3339, unix_now,
};
use crate::utils_inner::http::{send, RequestOptions};

/// The role an SSO profile signs in as, and where its token lives.
#[derive(Debug, PartialEq)]
struct SsoProfile {
    account_id: String,
    role_name: String,
    region: String,
    /// What `aws sso login` keys the token cache file by: the `sso-session` name, or the start URL
    /// for a legacy profile.
    token_key: String,
}

/// The `key = value` pairs of the config sections whose header name `matches`.
fn section_values(config: &str, matches: impl Fn(&str) -> bool) -> HashMap<String, String> {
    let mut values = HashMap::new();
    let mut in_section = false;
    for line in config.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_section = matches(trimmed[1..trimmed.len() - 1].trim());
            continue;
        }
        if !in_section {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            values.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    values
}

/// `profile` as an SSO profile in an AWS config file, or None when it is not one. A profile and
/// its `sso-session` may share a name, so the session section never counts as the profile.
fn find_profile(config: &str, profile: &str) -> Option<SsoProfile> {
    let values = section_values(config, |name| {
        !name.starts_with("sso-session ") && profile_section_matches(name, profile)
    });
    let (region, token_key) = match values.get("sso_session") {
        Some(session) => {
            let header = format!("sso-session {session}");
            let session_values = section_values(config, |name| name == header);
            (session_values.get("sso_region")?.clone(), session.clone())
        }
        None => (
            values.get("sso_region")?.clone(),
            values.get("sso_start_url")?.clone(),
        ),
    };
    Some(SsoProfile {
        account_id: values.get("sso_account_id")?.clone(),
        role_name: values.get("sso_role_name")?.clone(),
        region,
        token_key,
    })
}

/// Role credentials for `profile` when it is an SSO profile in the AWS config file text. `home`
/// holds `.aws/sso/cache`; `lookup` reads `AWS_ENDPOINT_URL_SSO`, the SDKs' portal endpoint
/// override. None when the profile is not an SSO profile, the cached token is missing or expired,
/// or the portal refuses it.
pub(crate) async fn credentials_from_sso(
    profile: &str,
    config: &str,
    lookup: impl Fn(&str) -> Option<String>,
    home: Option<&Path>,
) -> Option<AwsCredentials> {
    let sso = find_profile(config, profile)?;
    let now = unix_now();
    let token_file = home?.join(".aws/sso/cache").join(format!(
        "{}.json",
        hex::encode(Sha1::digest(sso.token_key.as_bytes()))
    ));
    let token = tokio::fs::read_to_string(&token_file)
        .await
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|cached| {
            // The AWS CLI v1 wrote `...UTC` rather than `...Z`.
            let expires_at = cached.get("expiresAt")?.as_str()?.replace("UTC", "Z");
            (parse_rfc3339(&expires_at)? > now)
                .then(|| cached.get("accessToken")?.as_str().map(str::to_string))?
        });
    let Some(token) = token else {
        tracing::warn!(
            profile,
            "AWS SSO token missing or expired; run `aws sso login --profile {profile}`"
        );
        return None;
    };
    let cache_key = format!("sso\0{profile}\0{token}");
    if let Some(credentials) = cached_credentials(&cache_key, now) {
        return Some(credentials);
    }

    let endpoint = lookup("AWS_ENDPOINT_URL_SSO")
        .unwrap_or_else(|| format!("https://portal.sso.{}.amazonaws.com", sso.region));
    let mut url = url::Url::parse(&format!(
        "{}/federation/credentials",
        endpoint.trim_end_matches('/')
    ))
    .ok()?;
    url.query_pairs_mut()
        .append_pair("account_id", &sso.account_id)
        .append_pair("role_name", &sso.role_name);
    let mut request = RequestOptions::new(reqwest::Method::GET, url.into());
    request
        .headers
        .push(("x-amz-sso_bearer_token".to_string(), token));
    let mut response = send(request).await.ok()?;
    let body = response.read_all_text().await.ok()?;
    if response.status != 200 {
        tracing::warn!(
            profile,
            status = response.status,
            "AWS SSO portal refused the cached token; run `aws sso login --profile {profile}`"
        );
        return None;
    }
    let body: Value = serde_json::from_str(&body).ok()?;
    let role = body.get("roleCredentials")?;
    let field = |name: &str| {
        role.get(name)
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .map(str::to_string)
    };
    let credentials = AwsCredentials {
        access_key_id: field("accessKeyId")?,
        secret_access_key: field("secretAccessKey")?,
        session_token: field("sessionToken"),
    };
    // `expiration` is epoch milliseconds; unreadable means use once, never cache.
    let expires_at = role
        .get("expiration")
        .and_then(Value::as_u64)
        .map_or(now, |millis| millis / 1000);
    cache_credentials(cache_key, &credentials, Some(expires_at));
    Some(credentials)
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// A one-request SSO portal: answers `status` with `body` and hands back the request head.
    async fn portal(status: u16, body: &str) -> (String, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let body = body.to_string();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 4096];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = socket.read(&mut chunk).await.unwrap();
                assert_ne!(read, 0, "request ended before its headers");
                request.extend_from_slice(&chunk[..read]);
            }
            let response = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&request).to_lowercase()
        });
        (endpoint, server)
    }

    /// Write the token `aws sso login` would cache for `token_key` under `home`.
    fn cache_token(home: &Path, token_key: &str, token: &str, expires_at: &str) {
        let dir = home.join(".aws/sso/cache");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(format!(
                "{}.json",
                hex::encode(Sha1::digest(token_key.as_bytes()))
            )),
            format!(
                r#"{{"accessToken":"{token}","expiresAt":"{expires_at}","region":"us-east-1"}}"#
            ),
        )
        .unwrap();
    }

    const ROLE_CREDENTIALS: &str = r#"{"roleCredentials":{"accessKeyId":"ASIASSO","secretAccessKey":"sso-secret","sessionToken":"sso-session-token","expiration":32503680000000}}"#;

    #[test]
    fn reads_legacy_and_sso_session_profiles() {
        let config = "[profile legacy]\nsso_start_url = https://legacy.awsapps.com/start\nsso_region = us-west-2\nsso_account_id = 111111111111\nsso_role_name = Legacy\n\n[profile shared]\nsso_session = shared\nsso_account_id = 222222222222\nsso_role_name = Shared\nregion = eu-west-1\n\n[sso-session shared]\nsso_start_url = https://shared.awsapps.com/start\nsso_region = eu-central-1\n\n[profile keys]\nregion = us-east-1\n";

        assert_eq!(
            [
                find_profile(config, "legacy"),
                find_profile(config, "shared"),
                find_profile(config, "keys"),
            ],
            [
                Some(SsoProfile {
                    account_id: "111111111111".into(),
                    role_name: "Legacy".into(),
                    region: "us-west-2".into(),
                    token_key: "https://legacy.awsapps.com/start".into(),
                }),
                Some(SsoProfile {
                    account_id: "222222222222".into(),
                    role_name: "Shared".into(),
                    region: "eu-central-1".into(),
                    token_key: "shared".into(),
                }),
                None,
            ]
        );
    }

    /// The cached token is sent to the portal for the profile's role, and the role credentials
    /// come back; a second resolution is served from the cache (the stub answers only once).
    #[tokio::test]
    async fn an_sso_profile_exchanges_its_cached_token_once() {
        let home = tempfile::tempdir().unwrap();
        let config = "[profile sso-stub-cached]\nsso_session = stub\nsso_account_id = 123456789012\nsso_role_name = BedrockUser\n\n[sso-session stub]\nsso_start_url = https://stub.awsapps.com/start\nsso_region = us-east-1\n";
        cache_token(home.path(), "stub", "cached-token", "2999-01-01T00:00:00Z");
        let (endpoint, server) = portal(200, ROLE_CREDENTIALS).await;
        let lookup = |var: &str| (var == "AWS_ENDPOINT_URL_SSO").then(|| endpoint.clone());

        let first =
            credentials_from_sso("sso-stub-cached", config, lookup, Some(home.path())).await;
        let request = server.await.unwrap();
        let second =
            credentials_from_sso("sso-stub-cached", config, lookup, Some(home.path())).await;

        let expected = Some(AwsCredentials {
            access_key_id: "ASIASSO".into(),
            secret_access_key: "sso-secret".into(),
            session_token: Some("sso-session-token".into()),
        });
        assert_eq!((first, second), (expected.clone(), expected));
        assert!(request.starts_with(
            "get /federation/credentials?account_id=123456789012&role_name=bedrockuser http/1.1"
        ));
        assert!(request.contains("x-amz-sso_bearer_token: cached-token\r\n"));
    }

    /// An expired token or one the portal rejects yields no credentials.
    #[tokio::test]
    async fn an_expired_or_rejected_token_yields_no_credentials() {
        let home = tempfile::tempdir().unwrap();
        let config = "[profile sso-stub-expired]\nsso_start_url = https://expired.awsapps.com/start\nsso_region = us-east-1\nsso_account_id = 123456789012\nsso_role_name = R\n\n[profile sso-stub-rejected]\nsso_start_url = https://rejected.awsapps.com/start\nsso_region = us-east-1\nsso_account_id = 123456789012\nsso_role_name = R\n";
        cache_token(
            home.path(),
            "https://expired.awsapps.com/start",
            "old-token",
            "2000-01-01T00:00:00UTC",
        );
        cache_token(
            home.path(),
            "https://rejected.awsapps.com/start",
            "revoked-token",
            "2999-01-01T00:00:00Z",
        );
        let (endpoint, server) =
            portal(401, r#"{"message":"Session token not found or invalid"}"#).await;
        let lookup = |var: &str| (var == "AWS_ENDPOINT_URL_SSO").then(|| endpoint.clone());

        let expired =
            credentials_from_sso("sso-stub-expired", config, lookup, Some(home.path())).await;
        let rejected =
            credentials_from_sso("sso-stub-rejected", config, lookup, Some(home.path())).await;

        assert_eq!((expired, rejected), (None, None));
        assert!(server
            .await
            .unwrap()
            .contains("x-amz-sso_bearer_token: revoked-token\r\n"));
    }
}
