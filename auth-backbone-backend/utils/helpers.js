import { pool } from "../db.js";
import { generateRefreshToken, hashToken } from "./tokens.js";

export async function createSessionForUser(userId, ip, ua, deviceFingerprint) {
  const refreshToken = generateRefreshToken();
  const refreshHash = hashToken(refreshToken);

  const q = `INSERT INTO sessions (user_id, refresh_token_hash, ip_address, user_agent, device_fingerprint, refresh_expires_at)
             VALUES ($1,$2,$3,$4,$5,NOW() + INTERVAL '7 days')
             RETURNING id, refresh_expires_at`;
  const r = await pool.query(q, [userId, refreshHash, ip || null, ua || null, deviceFingerprint || null]);

  return { refreshToken, sessionId: r.rows[0].id };
}


export function normalizePhone(phone) {
  if (!phone) return null;

  // remove all non-numeric characters
  const digits = phone.replace(/\D/g, "");

  // Pakistan phone format
  if (digits.startsWith("0")) {
    return "+92" + digits.slice(1);
  }

  if (!digits.startsWith("92")) {
    return "+92" + digits;
  }

  return "+" + digits;
}

