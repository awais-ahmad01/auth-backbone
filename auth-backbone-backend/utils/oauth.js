// backend/utils/oauth.js
import fetch from "node-fetch";

export async function exchangeGoogleCodeForTokens(code) {
  const params = new URLSearchParams();
  params.append("code", code);
  params.append("client_id", process.env.GOOGLE_CLIENT_ID);
  params.append("client_secret", process.env.GOOGLE_CLIENT_SECRET);
  params.append("redirect_uri", process.env.GOOGLE_OAUTH_CALLBACK);
  params.append("grant_type", "authorization_code");

  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString()
  });
  if (!r.ok) throw new Error("Failed to exchange code for tokens");
  return r.json(); // contains access_token, id_token, refresh_token, expires_in
}

export async function getGoogleUserInfo(access_token, id_token) {
  // id_token is a JWT with user info; we can decode or call userinfo endpoint
  const r = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
    headers: { Authorization: `Bearer ${access_token}` }
  });
  if (!r.ok) throw new Error("Failed to fetch Google user info");
  return r.json(); // contains sub, email, email_verified, name, picture, etc
}
