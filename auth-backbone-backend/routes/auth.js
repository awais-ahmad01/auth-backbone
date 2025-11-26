import express from "express";
import { authMiddleware } from "../middleware/authMiddleware.js";
const router = express.Router();

import {


  signup,
  verifyEmail,
  login,
  refreshToken,
  me,
  magicLinkRequest,
  magicLinkConsume,
  oauthGoogleUrl,
  oauthGoogleCallback,
  oauthLinkConfirm,
  forgotPassword,
  resetPassword,
  requestOtp,
  verifyOtp,
} from "../controllers/auth.js";

router.post("/signup", signup);

// ---------------------------------------------
// VERIFY EMAIL
// ---------------------------------------------
router.post("/verify-email", verifyEmail);

// ---------------------------------------------
// LOGIN
// ---------------------------------------------
router.post("/login", login);

// ---------------------------------------------
// REFRESH (ROTATING TOKENS)
// ---------------------------------------------
router.post("/refresh", refreshToken);

router.get("/me", authMiddleware, me);

// -------------------------------
// MAGIC LINK: REQUEST
// -------------------------------
router.post("/magic/request", magicLinkRequest);

// -------------------------------
// MAGIC LINK: CONSUME
// -------------------------------
router.post("/magic/consume", magicLinkConsume);

// -------------------------------
// OAUTH: START (redirect user to Google)
// -------------------------------
router.get("/oauth/google/url", oauthGoogleUrl);

// -------------------------------
// OAUTH: CALLBACK (server receives code)
// -------------------------------
router.get("/oauth/google/callback", oauthGoogleCallback);

// -------------------------------
// OAUTH LINK CONFIRM (for provider emails that were unverified)
// -------------------------------
// Frontend calls this after user clicks link in email sent by provider linking step.
// It will finalize linking (insert into accounts table) and then sign user in.
router.post("/oauth/link/confirm", oauthLinkConfirm);

// -------------------------------
// FORGOT PASSWORD - request reset
// -------------------------------
router.post("/forgot-password", forgotPassword);

// -------------------------------
// RESET PASSWORD - consume token & set new password
// -------------------------------
router.post("/reset-password", resetPassword);

// REQUEST OTP
router.post("/otp/request", requestOtp);

// VERIFY OTP
router.post("/otp/verify", verifyOtp);

export default router;
