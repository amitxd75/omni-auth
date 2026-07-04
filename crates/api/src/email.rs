//! Outbound transactional email dispatcher.
//! Utilizes Resend REST API for delivery, falling back to local console logging in development.

use crate::middleware::AppState;
use serde_json::json;

// ── Shared helper ─────────────────────────────────────────────────────────────

/// Helper function executing an asynchronous HTTP POST payload to the Resend API.
async fn dispatch_email(
    api_key: String,
    from_email: String,
    to_email: &str,
    subject: &str,
    html: &str,
) {
    let client = reqwest::Client::new();
    let payload = json!({
        "from": from_email,
        "to": [to_email],
        "subject": subject,
        "html": html,
    });

    let res = client
        .post("https://api.resend.com/emails")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await;

    match res {
        Ok(response) => {
            if response.status().is_success() {
                tracing::info!("✉️ Email sent successfully to {}", to_email);
            } else {
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                tracing::error!("✉️ Resend error {} for {}: {}", status, to_email, text);
            }
        }
        Err(e) => {
            tracing::error!("✉️ Failed to dispatch email to Resend: {:?}", e);
        }
    }
}

/// Helper extracting and validating the Resend API credentials from server state settings.
/// Returns `None` if unconfigured or using standard mock string variables.
fn resend_credentials(state: &AppState) -> Option<(String, String)> {
    let key = state.config.resend_api_key.clone()?;
    if key.is_empty() || key.contains("your_api_key") {
        return None;
    }
    let from = state
        .config
        .resend_from_email
        .clone()
        .unwrap_or_else(|| "onboarding@resend.dev".to_string());
    Some((key, from))
}

// ── Email functions ────────────────────────────────────────────────────────────

/// Dispatches a one-time OTP registration confirmation code to the user.
/// Spawns a background task so it doesn't block the caller's request execution loop.
pub fn send_verification_email(state: &AppState, to_email: String, code: String) {
    let creds = resend_credentials(state);

    tokio::spawn(async move {
        tracing::info!("✉️  [OTP] Verification code for {} → {}", to_email, code);

        if let Some((api_key, from_email)) = creds {
            dispatch_email(
                api_key,
                from_email,
                &to_email,
                "Verify your email address — OmniAuth",
                &format!(
                    "<p>Thanks for signing up! Verify your email with this code:</p>\
                     <h2 style='font-family:monospace;letter-spacing:4px;font-size:32px'>{code}</h2>\
                     <p>This code expires in <strong>15 minutes</strong>.</p>"
                ),
            )
            .await;
        } else {
            tracing::info!("✉️  Resend not configured — OTP logged above only.");
        }
    });
}

/// Dispatches a password recovery email containing a one-click verification reset link.
/// The link redirects the user to the configured frontend app page.
pub fn send_password_reset_email(state: &AppState, to_email: String, reset_token: String) {
    let creds = resend_credentials(state);
    let frontend_url = state.config.frontend_url.clone();

    tokio::spawn(async move {
        // URL-encode the email to handle + signs etc.
        let encoded_email = to_email.replace('+', "%2B").replace('@', "%40");
        let reset_link =
            format!("{frontend_url}/?reset_token={reset_token}&reset_email={encoded_email}");

        tracing::info!("🔑 [Password Reset] Link for {} → {}", to_email, reset_link);

        if let Some((api_key, from_email)) = creds {
            dispatch_email(
                api_key,
                from_email,
                &to_email,
                "Reset your OmniAuth password",
                &format!(
                    "<p>You requested a password reset. Click the link below to set a new password:</p>\
                     <p><a href='{reset_link}' style='display:inline-block;padding:12px 24px;background:#6366f1;\
                     color:#fff;text-decoration:none;border-radius:8px;font-weight:bold'>Reset Password</a></p>\
                     <p>Or copy this URL into your browser:</p>\
                     <p style='font-family:monospace;word-break:break-all;font-size:12px'>{reset_link}</p>\
                     <p>This link expires in <strong>30 minutes</strong> and can only be used once.<br>\
                     If you didn't request this, you can safely ignore this email.</p>"
                ),
            )
            .await;
        } else {
            tracing::info!("✉️  Resend not configured — reset link logged above only.");
        }
    });
}

/// Dispatches a passwordless "magic link" sign-in email.
/// Clicking the button logs the user in directly by passing a short-lived token parameter.
pub fn send_magic_link_email(state: &AppState, to_email: String, magic_token: String) {
    let creds = resend_credentials(state);
    let frontend_url = state.config.frontend_url.clone();

    tokio::spawn(async move {
        let encoded_email = to_email.replace('+', "%2B").replace('@', "%40");
        let magic_link =
            format!("{frontend_url}/?magic_token={magic_token}&magic_email={encoded_email}");

        tracing::info!(
            "🔗 [Magic Link] Login link for {} → {}",
            to_email,
            magic_link
        );

        if let Some((api_key, from_email)) = creds {
            dispatch_email(
                api_key,
                from_email,
                &to_email,
                "Your OmniAuth sign-in link",
                &format!(
                    "<p>Click the button below to sign in instantly — no password needed.</p>\
                     <p><a href='{magic_link}' style='display:inline-block;padding:12px 24px;background:#6366f1;\
                     color:#fff;text-decoration:none;border-radius:8px;font-weight:bold'>Sign In to OmniAuth</a></p>\
                     <p>Or copy this URL into your browser:</p>\
                     <p style='font-family:monospace;word-break:break-all;font-size:12px'>{magic_link}</p>\
                     <p>This link expires in <strong>15 minutes</strong> and can only be used once.<br>\
                     If you didn't request this, you can safely ignore this email.</p>"
                ),
            )
            .await;
        } else {
            tracing::info!("✉️  Resend not configured — magic link logged above only.");
        }
    });
}
