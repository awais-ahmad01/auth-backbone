import express from "express";
import crypto from "crypto";
import argon2 from "argon2";
import { pool } from "../db.js";
import { sendVerificationEmail, sendMagicLinkEmail } from "../utils/sendEmail.js";
import { generateAccessToken, generateRefreshToken, hashToken } from "../utils/tokens.js";
import { authMiddleware } from "../middleware/authMiddleware.js";
import { exchangeGoogleCodeForTokens, getGoogleUserInfo } from "../utils/oauth.js";

const REFRESH_COOKIE_NAME = process.env.REFRESH_COOKIE_NAME || "refresh_token";

const MAGIC_LINK_EXPIRY_MINUTES = 15;


const router = express.Router();


router.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  const existing = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
  if (existing.rowCount > 0)
    return res.status(400).json({ error: "Email already exists" });

  const passwordHash = await argon2.hash(password);

  const user = await pool.query(
    `INSERT INTO users (email, password_hash, name)
     VALUES ($1, $2, $3) RETURNING *`,
    [email, passwordHash, name]
  );

  const token = crypto.randomBytes(32).toString("hex");
  const tokenHash = hashToken(token);

  await pool.query(
    `INSERT INTO verification_tokens (identifier, token_hash, type, expires_at)
     VALUES ($1, $2, 'email_verification', NOW() + INTERVAL '15 minutes')`,
    [email, tokenHash]
  );

  await sendVerificationEmail(email, token);

  res.json({ message: "Verification email sent" });
});


// ---------------------------------------------
// VERIFY EMAIL
// ---------------------------------------------
router.post("/verify-email", async (req, res) => {
  const { token } = req.body;

  const tokenHash = hashToken(token);

  const dbToken = await pool.query(
    `SELECT * FROM verification_tokens
     WHERE token_hash=$1 AND type='email_verification'`,
    [tokenHash]
  );

  if (dbToken.rowCount === 0)
    return res.status(400).json({ error: "Invalid or expired token" });

  const email = dbToken.rows[0].identifier;

  await pool.query(`UPDATE users SET email_verified=true WHERE email=$1`, [email]);
  await pool.query(`DELETE FROM verification_tokens WHERE identifier=$1`, [email]);

  res.json({ message: "Email verified successfully" });
});


// ---------------------------------------------
// LOGIN
// ---------------------------------------------
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const userQuery = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
  if (userQuery.rowCount === 0)
    return res.status(400).json({ error: "Invalid credentials" });

  const user = userQuery.rows[0];

  if (!user.email_verified)
    return res.status(400).json({ error: "Verify email first" });

  const validPassword = await argon2.verify(user.password_hash, password);
  if (!validPassword)
    return res.status(400).json({ error: "Invalid credentials" });

  const refreshToken = generateRefreshToken();
  const refreshHash = hashToken(refreshToken);

  await pool.query(
    `INSERT INTO sessions (user_id, refresh_token_hash, refresh_expires_at)
     VALUES ($1, $2, NOW() + INTERVAL '7 days')`,
    [user.id, refreshHash]
  );

  const accessToken = generateAccessToken(user);

  res.cookie("refresh_token", refreshToken, {
    httpOnly: true,
    secure: false,
    sameSite: "lax",
    path: "/"
  });

  res.json({ accessToken, user: { id: user.id, email: user.email, name: user.name } });
});


// ---------------------------------------------
// REFRESH (ROTATING TOKENS)
// ---------------------------------------------
router.post("/refresh", async (req, res) => {
  const refreshToken = req.cookies.refresh_token;
  if (!refreshToken) return res.status(401).json({ error: "No refresh token" });

  const refreshHash = hashToken(refreshToken);

  const session = await pool.query(
    `SELECT * FROM sessions WHERE refresh_token_hash=$1 AND is_revoked=false`,
    [refreshHash]
  );

  if (session.rowCount === 0)
    return res.status(401).json({ error: "Invalid refresh token" });

  const userId = session.rows[0].user_id;

  const userQuery = await pool.query(`SELECT * FROM users WHERE id=$1`, [userId]);
  const user = userQuery.rows[0];

  // Rotate refresh token
  const newRefreshToken = generateRefreshToken();
  const newHash = hashToken(newRefreshToken);

  await pool.query(
    `UPDATE sessions SET refresh_token_hash=$1, last_used_at=NOW() WHERE id=$2`,
    [newHash, session.rows[0].id]
  );

  const accessToken = generateAccessToken(user);

  res.cookie("refresh_token", newRefreshToken, {
    httpOnly: true,
    secure: false,
    sameSite: "lax",
    path: "/"
  });

  res.json({ accessToken });
});



router.get("/me", authMiddleware, async (req, res) => {
  const userId = req.user.id;

  const user = await pool.query(
    "SELECT id, name, email FROM users WHERE id=$1",
    [userId]
  );

  res.json(user.rows[0]);
});




// --- Helper: create session (re-uses existing session logic; rotates handled elsewhere) ---
async function createSessionForUser(userId, ip, ua, deviceFingerprint) {
  const refreshToken = generateRefreshToken();
  const refreshHash = hashToken(refreshToken);

  const q = `INSERT INTO sessions (user_id, refresh_token_hash, ip_address, user_agent, device_fingerprint, refresh_expires_at)
             VALUES ($1,$2,$3,$4,$5,NOW() + INTERVAL '7 days')
             RETURNING id, refresh_expires_at`;
  const r = await pool.query(q, [userId, refreshHash, ip || null, ua || null, deviceFingerprint || null]);

  return { refreshToken, sessionId: r.rows[0].id };
}

// -------------------------------
// MAGIC LINK: REQUEST
// -------------------------------
router.post("/magic/request", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email required" });

    // generate token
    const token = crypto.randomBytes(32).toString("hex");
    const tokenHash = hashToken(token);

    // store token hashed
    const q = `INSERT INTO verification_tokens (identifier, token_hash, type, expires_at)
               VALUES ($1,$2,'magic_link', NOW() + INTERVAL '${MAGIC_LINK_EXPIRY_MINUTES} minutes')`;
    await pool.query(q, [email, tokenHash]);

    // send magic link to user -> link points to frontend route that will call /auth/magic/consume
    const magicUrl = `${process.env.FRONTEND_URL}/magic/consume?token=${token}&email=${encodeURIComponent(email)}`;

    // send email (use a dedicated sendMagicLinkEmail)
    await sendMagicLinkEmail(email, magicUrl);

    return res.json({ message: "Magic link sent if the email exists" });
  } catch (err) {
    console.error("magic/request err:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// -------------------------------
// MAGIC LINK: CONSUME
// -------------------------------
router.post("/magic/consume", async (req, res) => {
  try {
    const { token, email } = req.body;
    if (!token || !email) return res.status(400).json({ error: "Invalid request" });

    const tokenHash = hashToken(token);

    // find token row
    const tokQ = `SELECT * FROM verification_tokens
                  WHERE token_hash=$1 AND type='magic_link' AND identifier=$2 AND expires_at > NOW()`;
    const tokR = await pool.query(tokQ, [tokenHash, email]);

    if (tokR.rowCount === 0) {
      return res.status(400).json({ error: "Invalid or expired magic link" });
    }

    // single-use: delete token immediately
    await pool.query(`DELETE FROM verification_tokens WHERE token_hash=$1`, [tokenHash]);

    // find user, or create if not exists
    let userRes = await pool.query("SELECT * FROM users WHERE email=$1", [email]);

    if (userRes.rowCount === 0) {
      // create account (email_verified true because user confirmed via email link)
      const create = await pool.query(
        `INSERT INTO users (email, email_verified) VALUES ($1, true) RETURNING *`,
        [email]
      );
      userRes = create;
    } else {
      // ensure email_verified true
      await pool.query(`UPDATE users SET email_verified=true WHERE email=$1`, [email]);
    }

    const user = userRes.rows[0];

    // Create session & send cookie
    const ip = req.ip;
    const ua = req.get("User-Agent") || "";
    const deviceFingerprint = req.body.deviceFingerprint || null;

    const { refreshToken } = await createSessionForUser(user.id, ip, ua, deviceFingerprint);
    const accessToken = generateAccessToken(user);

    // Set http-only cookie
    res.cookie(REFRESH_COOKIE_NAME, refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/"
    });

    return res.json({ accessToken, user: { id: user.id, email: user.email } });
  } catch (err) {
    console.error("magic/consume err:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// -------------------------------
// OAUTH: START (redirect user to Google)
// -------------------------------
router.get("/oauth/google/url", (req, res) => {
  // optional "returnTo" param to redirect back after login
  const state = crypto.randomBytes(16).toString("hex");
  // store `state` in cookie for CSRF/state validation, short-lived
  res.cookie("oauth_state", state, { httpOnly: true, sameSite: "lax", maxAge: 1000 * 60 * 5 });

  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: process.env.GOOGLE_OAUTH_CALLBACK,
    response_type: "code",
    scope: "openid email profile",
    access_type: "offline",
    prompt: "consent",
    state
  });

  const url = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
  res.json({ url });
});

// -------------------------------
// OAUTH: CALLBACK (server receives code)
// -------------------------------
router.get("/oauth/google/callback", async (req, res) => {
  const { code, state } = req.query;
  const cookieState = req.cookies.oauth_state;
  try {
    if (!code) return res.status(400).send("Missing code");

    // validate state
    if (!state || !cookieState || state !== cookieState) {
      return res.status(400).send("Invalid state");
    }

    // exchange code for tokens
    const tokens = await exchangeGoogleCodeForTokens(code);
    const access_token = tokens.access_token;
    // Get user info
    const profile = await getGoogleUserInfo(access_token);
    // profile: { sub, email, email_verified, name, picture, ... }
    const provider = "google";
    const provider_account_id = profile.sub;
    const provider_email = profile.email;
    const provider_email_verified = !!profile.email_verified;

    // --- Account linking logic ---
    // 1) Does an accounts row with this provider+provider_account_id already exist?
    const accQ = `SELECT * FROM accounts WHERE provider=$1 AND provider_account_id=$2`;
    const accR = await pool.query(accQ, [provider, provider_account_id]);

    let user;
    if (accR.rowCount > 0) {
      // Existing provider account -> log in that user
      const userId = accR.rows[0].user_id;
      const uR = await pool.query(`SELECT * FROM users WHERE id=$1`, [userId]);
      user = uR.rows[0];
    } else {
      // No existing provider account - does a local user exist with the provider email?
      const userEmailQ = await pool.query(`SELECT * FROM users WHERE email=$1`, [provider_email]);

      if (userEmailQ.rowCount > 0) {
        // A local user already exists with same email:
        // Only auto-link if provider email is verified.
        if (provider_email_verified) {
          // create accounts row linking to existing user
          const userId = userEmailQ.rows[0].id;
          await pool.query(
            `INSERT INTO accounts (user_id, provider, provider_account_id, provider_email, provider_email_verified)
             VALUES ($1,$2,$3,$4,$5)`,
            [userId, provider, provider_account_id, provider_email, provider_email_verified]
          );
          user = userEmailQ.rows[0];
        } else {
          // Provider email not verified -> require additional verification:
          // Create a pending link workflow: generate an email verification token to provider_email (owner).
          // For simplicity, create verification token and send a verification email with a link back to frontend to confirm linking.
          const token = crypto.randomBytes(32).toString("hex");
          const tokenHash = hashToken(token);
          await pool.query(
            `INSERT INTO verification_tokens (identifier, token_hash, type, expires_at)
             VALUES ($1,$2,'oauth_link', NOW() + INTERVAL '15 minutes')`,
            [provider_email, tokenHash]
          );
          // send user email with link to confirm linking (frontend will call /auth/oauth/link/confirm)
          const confirmUrl = `${process.env.FRONTEND_URL}/oauth/link-confirm?token=${token}&provider=${provider}&provider_id=${provider_account_id}&email=${encodeURIComponent(provider_email)}`;
          await sendVerificationEmail(provider_email, confirmUrl);
          return res.send("Provider email not verified. A verification email was sent to confirm linking.");
        }
      } else {
        // No local user with that email: create new user and link
        // Trust provider email only if verified. If not verified, still create user but set email_verified=false.
        const emailVerified = provider_email_verified ? true : false;
        const createU = await pool.query(
          `INSERT INTO users (email, email_verified, name) VALUES ($1,$2,$3) RETURNING *`,
          [provider_email, emailVerified, profile.name || null]
        );
        const userRow = createU.rows[0];
        await pool.query(
          `INSERT INTO accounts (user_id, provider, provider_account_id, provider_email, provider_email_verified)
           VALUES ($1,$2,$3,$4,$5)`,
          [userRow.id, provider, provider_account_id, provider_email, provider_email_verified]
        );
        user = userRow;
      }
    }

    // create session for user & set cookie + redirect to frontend (or return JSON)
    const ip = req.ip;
    const ua = req.get("User-Agent") || "";
    const { refreshToken } = await createSessionForUser(user.id, ip, ua, null);

    // set cookie
    res.cookie(REFRESH_COOKIE_NAME, refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/"
    });

    // redirect back to frontend (e.g., /oauth/success), or send JSON if used by SPA flow
    return res.redirect(`${process.env.FRONTEND_URL}/oauth/success`);
  } catch (err) {
    console.error("oauth callback error:", err);
    return res.status(500).send("OAuth callback error");
  }
});

// -------------------------------
// OAUTH LINK CONFIRM (for provider emails that were unverified)
// -------------------------------
// Frontend calls this after user clicks link in email sent by provider linking step.
// It will finalize linking (insert into accounts table) and then sign user in.
router.post("/oauth/link/confirm", async (req, res) => {
  try {
    const { token, provider, provider_id, email } = req.body;
    if (!token || !provider || !provider_id || !email) return res.status(400).json({ error: "Invalid request" });

    const tokenHash = hashToken(token);
    const tokQ = `SELECT * FROM verification_tokens WHERE token_hash=$1 AND type='oauth_link' AND identifier=$2 AND expires_at > NOW()`;
    const tokR = await pool.query(tokQ, [tokenHash, email]);

    if (tokR.rowCount === 0) return res.status(400).json({ error: "Invalid or expired token" });

    // delete token
    await pool.query(`DELETE FROM verification_tokens WHERE token_hash=$1`, [tokenHash]);

    // ensure user exists
    let userQ = await pool.query(`SELECT * FROM users WHERE email=$1`, [email]);
    let user;
    if (userQ.rowCount === 0) {
      const createU = await pool.query(`INSERT INTO users (email, email_verified) VALUES ($1, true) RETURNING *`, [email]);
      user = createU.rows[0];
    } else {
      user = userQ.rows[0];
      // mark email verified
      await pool.query(`UPDATE users SET email_verified=true WHERE id=$1`, [user.id]);
    }

    // insert accounts row if not exists
    const exists = await pool.query(`SELECT 1 FROM accounts WHERE provider=$1 AND provider_account_id=$2`, [provider, provider_id]);
    if (exists.rowCount === 0) {
      await pool.query(
        `INSERT INTO accounts (user_id, provider, provider_account_id, provider_email, provider_email_verified)
         VALUES ($1,$2,$3,$4,true)`,
        [user.id, provider, provider_id, email]
      );
    }

    // create session & set cookie
    const { refreshToken } = await createSessionForUser(user.id, req.ip, req.get("User-Agent") || "", null);
    res.cookie(REFRESH_COOKIE_NAME, refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/"
    });

    return res.json({ accessToken: generateAccessToken(user), user: { id: user.id, email: user.email } });
  } catch (err) {
    console.error("oauth/link/confirm err:", err);
    return res.status(500).json({ error: "Server error" });
  }
});




export default router;
