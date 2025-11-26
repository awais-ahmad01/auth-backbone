import crypto from "crypto";
import argon2 from "argon2";
import { pool } from "../db.js";
import { sendVerificationEmail, sendMagicLinkEmail, sendPasswordResetEmail } from "../utils/sendEmail.js";
import { generateAccessToken, generateRefreshToken, hashToken } from "../utils/tokens.js";
import { exchangeGoogleCodeForTokens, getGoogleUserInfo } from "../utils/oauth.js";
import { sendOtpSms } from "../utils/sendSMS.js";
import { normalizePhone, createSessionForUser } from "../utils/helpers.js";

const REFRESH_COOKIE_NAME = process.env.REFRESH_COOKIE_NAME || "refresh_token";

const MAGIC_LINK_EXPIRY_MINUTES = 15;
const PASSWORD_RESET_EXP_MINUTES = 15;



export const signup = async (req, res) => {
   const { name, email, phone, password } = req.body;

  if (!name || !email || !phone || !password) {
    return res.status(400).json({ error: "All fields required" });
  }

  // format phone
  const formattedPhone = normalizePhone(phone);

  
  // check if phone already exists
  const phoneCheck = await pool.query("SELECT id FROM users WHERE phone=$1", [formattedPhone]);
  if (phoneCheck.rowCount > 0) {
    return res.status(400).json({ error: "Phone number already registered" });
  }

  const existing = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
  if (existing.rowCount > 0)
    return res.status(400).json({ error: "Email already exists" });

  const passwordHash = await argon2.hash(password);

 
  const user = await pool.query(
    `INSERT INTO users (name, email, phone, password_hash, email_verified)
     VALUES ($1, $2, $3, $4, false)
     RETURNING *`,
    [name, email, formattedPhone, passwordHash]
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
}




export const verifyEmail = async (req, res) => {
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
}


export const login = async (req, res) => {
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
}


// export const login = async (req, res) => {
//   const { email, password } = req.body;
//   console.log("Login attempt for email:", email);
//   const ip = req.ip;
//   const userAgent = req.get("User-Agent") || "";

//   if (!email || !password) {
//     return res.status(400).json({ error: "Email and password required" });
//   }

//   // Record login attempt function
//   const recordAttempt = async (success, reason = null) => {
//     await pool.query(
//       `INSERT INTO login_attempts (user_identifier, ip_address, user_agent, success, reason, created_at)
//        VALUES ($1, $2, $3, $4, $5, NOW())`,
//       [email, ip, userAgent, success, reason]
//     );
//   };

//   console.log("=== BRUTE FORCE CHECK START ===");
//   console.log("Checking for email:", email);

//   // --- Improved Brute force detection ---
//   const LOCK_THRESHOLD = 5; // 5 failed attempts
//   const LOCK_TIME_MINUTES = 5;

//   // Get failed attempts in last 5 minutes
//   const failQ = await pool.query(
//     `SELECT COUNT(*) FROM login_attempts
//      WHERE user_identifier=$1 AND success=false AND created_at > NOW() - INTERVAL '5 minutes'`,
//     [email]
//   );

//   const failCount = parseInt(failQ.rows[0].count, 10);
//   console.log("Failed attempts in last 5 minutes:", failCount);

//   // Check if account should be locked
//   if (failCount >= LOCK_THRESHOLD) {
//     // Get the most recent failed attempt time
//     const lastFailedQ = await pool.query(
//       `SELECT created_at FROM login_attempts
//        WHERE user_identifier=$1 AND success=false
//        ORDER BY created_at DESC LIMIT 1`,
//       [email]
//     );

//     if (lastFailedQ.rows.length > 0) {
//       const lastFailTime = new Date(lastFailedQ.rows[0].created_at);
//       const now = new Date();
//       const diffMinutes = (now - lastFailTime) / 1000 / 60;
      
//       console.log("Last failed attempt:", lastFailTime);
//       console.log("Time since last failure (minutes):", diffMinutes);

//       if (diffMinutes < LOCK_TIME_MINUTES) {
//         const remainingTime = Math.ceil(LOCK_TIME_MINUTES - diffMinutes);
//         console.log(`Account LOCKED. Try again in ${remainingTime} minute(s)`);
        
//         await recordAttempt(false, "Account locked due to repeated failures");
//         return res.status(403).json({
//           error: `Account locked due to too many failed attempts. Try again in ${remainingTime} minute(s)`
//         });
//       } else {
//         console.log("Lock period expired, resetting counter");
//         // Lock period has expired, allow attempt to continue
//       }
//     }
//   }
//   console.log("=== BRUTE FORCE CHECK END ===");

//   // Fetch user if exists
//   const userQuery = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
//   const user = userQuery.rows[0];

//   // If user not found
//   if (!user) {
//     console.log("User not found for email:", email);
//     await recordAttempt(false, "Invalid credentials");
//     return res.status(400).json({ error: "Invalid credentials" });
//   }

//   if (!user.email_verified) {
//     console.log("Email not verified for:", email);
//     await recordAttempt(false, "Email not verified");
//     return res.status(400).json({ error: "Verify email first" });
//   }

//   const validPassword = await argon2.verify(user.password_hash, password);
//   if (!validPassword) {
//     console.log("Invalid password for:", email);
//     await recordAttempt(false, "Invalid credentials");
//     return res.status(400).json({ error: "Invalid credentials" });
//   }

//   // Success: record successful attempt
//   console.log("Login successful for:", email);
//   await recordAttempt(true);

//   const refreshToken = generateRefreshToken();
//   const refreshHash = hashToken(refreshToken);

//   await pool.query(
//     `INSERT INTO sessions (user_id, refresh_token_hash, refresh_expires_at, ip_address, user_agent)
//      VALUES ($1, $2, NOW() + INTERVAL '7 days', $3, $4)`,
//     [user.id, refreshHash, ip, userAgent]
//   );

//   const accessToken = generateAccessToken(user);

//   res.cookie("refresh_token", refreshToken, {
//     httpOnly: true,
//     secure: process.env.NODE_ENV === "production",
//     sameSite: "lax",
//     path: "/"
//   });

//   res.json({ accessToken, user: { id: user.id, email: user.email, name: user.name } });
// };



export const refreshToken = async (req, res) => {
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
}




export const me = async (req, res) => {
  const userId = req.user.id;

  const user = await pool.query(
    "SELECT id, name, email FROM users WHERE id=$1",
    [userId]
  );

  res.json(user.rows[0]);
}



export const magicLinkRequest = async (req, res) => {
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
}



export const magicLinkConsume = async (req, res) => {
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
}



export const oauthGoogleUrl = (req, res) => {
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
}




export const oauthGoogleCallback = async (req, res) => {
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
}



export const oauthLinkConfirm = async (req, res) => {
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
}



export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email required" });

    // Always return generic success to avoid disclosing which emails exist
    // But only generate token if user exists
    const userQ = await pool.query("SELECT id, email_verified FROM users WHERE email=$1", [email]);
    if (userQ.rowCount === 0) {
      // still respond with success to prevent enumeration
      return res.json({ message: "If an account exists, a password reset email was sent." });
    }

    const user = userQ.rows[0];

    // Optionally require email verified before password reset — typical to require verification
    // If you want to require verified: uncomment below:
    // if (!user.email_verified) return res.status(400).json({ error: "Email not verified" });

    // Generate token and store hashed version
    const token = crypto.randomBytes(32).toString("hex");
    const tokenHash = hashToken(token);

    // before INSERT in forgot-password route:
await pool.query(`DELETE FROM verification_tokens WHERE identifier=$1 AND type='password_reset'`, [email]);


    // Store token (single use)
    await pool.query(
      `INSERT INTO verification_tokens (identifier, token_hash, type, expires_at)
       VALUES ($1,$2,'password_reset', NOW() + INTERVAL '${PASSWORD_RESET_EXP_MINUTES} minutes')`,
      [email, tokenHash]
    );

    // Build reset URL (frontend will have route to consume token)
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${token}&email=${encodeURIComponent(email)}`;

    // Send reset email
    await sendPasswordResetEmail(email, resetUrl);

    // Generic success
    return res.json({ message: "If an account exists, a password reset email was sent." });
  } catch (err) {
    console.error("forgot-password err:", err);
    return res.status(500).json({ error: "Server error" });
  }
}


export const resetPassword = async (req, res) => {
  try {
    const { token, email, newPassword } = req.body;
    if (!token || !email || !newPassword) return res.status(400).json({ error: "Missing parameters" });

    const tokenHash = hashToken(token);

    // Find token record
    const tokQ = await pool.query(
      `SELECT * FROM verification_tokens WHERE token_hash=$1 AND type='password_reset' AND identifier=$2 AND expires_at > NOW()`,
      [tokenHash, email]
    );

    if (tokQ.rowCount === 0) {
      return res.status(400).json({ error: "Invalid or expired password reset token" });
    }

    // Consume token (single-use)
    await pool.query(`DELETE FROM verification_tokens WHERE token_hash=$1`, [tokenHash]);

    // Find user
    const userQ = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (userQ.rowCount === 0) {
      // Should not happen normally (email existed when token generated)
      return res.status(400).json({ error: "User not found" });
    }
    const user = userQ.rows[0];

    // Hash new password with Argon2id
    const newHash = await argon2.hash(newPassword);

    // Update user's password and bump token_version (invalidate access tokens)
    await pool.query(
      `UPDATE users SET password_hash=$1, token_version = token_version + 1, updated_at = NOW() WHERE id=$2`,
      [newHash, user.id]
    );

    // Invalidate all existing sessions (delete sessions rows) — immediate logout everywhere
    await pool.query(`DELETE FROM sessions WHERE user_id=$1`, [user.id]);

    // Optionally: create a new session and issue fresh refresh cookie + access token so user stays logged in
    // Here we will return generic success; frontend can redirect to sign-in page
    return res.json({ message: "Password has been reset. Please sign in with your new password." });
  } catch (err) {
    console.error("reset-password err:", err);
    return res.status(500).json({ error: "Server error" });
  }
}


export const requestOtp = async (req, res) => {
  try {
    const rawPhone = req.body.phone;
    const phone = normalizePhone(rawPhone);

    if (!phone) return res.status(400).json({ error: "Phone required" });

    // check if phone exists in users table
    const u = await pool.query("SELECT id FROM users WHERE phone=$1", [phone]);
    if (u.rowCount === 0) {
      return res.status(400).json({ error: "Phone number not registered" });
    }

    // generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpHash = hashToken(otp);

    await pool.query("DELETE FROM phone_otps WHERE phone=$1", [phone]);

    await pool.query(
      `INSERT INTO phone_otps (phone, otp_hash, expires_at)
       VALUES ($1, $2, NOW() + INTERVAL '5 minutes')`,
      [phone, otpHash]
    );

    await sendOtpSms(phone, otp);

    return res.json({ message: "OTP sent" });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Failed to send OTP" });
  }
}



export const verifyOtp = async (req, res) => {
  try {
    const { phone, otp } = req.body;
    if (!phone || !otp) return res.status(400).json({ error: "Missing params" });

    const otpHash = hashToken(otp);

    const q = await pool.query(
      `SELECT * FROM phone_otps
       WHERE phone=$1 AND otp_hash=$2 AND expires_at > NOW() AND used=false`,
      [phone, otpHash]
    );

    if (q.rowCount === 0) {
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }

    // mark used
    await pool.query(
      "UPDATE phone_otps SET used=true WHERE phone=$1 AND otp_hash=$2",
      [phone, otpHash]
    );

    // get user
    const userQ = await pool.query("SELECT * FROM users WHERE phone=$1", [phone]);
    if (userQ.rowCount === 0) {
      return res.status(400).json({ error: "Phone number not registered" });
    }

    const user = userQ.rows[0];

    // Create tokens
    const accessToken = generateAccessToken(user.id, user.token_version);
    const refreshToken = generateRefreshToken();
    const refreshHash = hashToken(refreshToken);

    // FIXED INSERT — includes refresh_expires_at
    await pool.query(
      `INSERT INTO sessions (user_id, refresh_token_hash, refresh_expires_at, user_agent, ip_address)
       VALUES ($1, $2, NOW() + INTERVAL '30 days', $3, $4)`,
      [user.id, refreshHash, req.headers["user-agent"] || "", req.ip]
    );

    res.cookie("refresh_token", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/",
    });

    return res.json({ message: "OTP verified", accessToken });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "OTP verification failed" });
  }
}





