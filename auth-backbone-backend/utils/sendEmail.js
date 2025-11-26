import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_FROM,
      pass: process.env.EMAIL_PASS
    }
  });

export async function sendVerificationEmail(email, token) {
  const url = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;

  console.log("Sending verification email to:", email);

  await transporter.sendMail({
    from: process.env.EMAIL_FROM,
    to: email,
    subject: "Verify your email",
    html: `Click here to verify: <a href="${url}">${url}</a>`
  });

  console.log("Verification email sent to:", email);
}


const MAGIC_LINK_EXPIRY_MINUTES = 15;

export async function sendMagicLinkEmail(email, url) {
  const html = `<p>Sign in by clicking the link below (valid for ${MAGIC_LINK_EXPIRY_MINUTES || 15} minutes):</p>
                <p><a href="${url}">${url}</a></p>`;
  await transporter.sendMail({
    from: process.env.EMAIL_FROM,
    to: email,
    subject: "Your magic sign-in link",
    html
  });
}



// backend/utils/sendEmail.js
// ... existing imports and transporter setup

export async function sendPasswordResetEmail(email, resetUrl) {
  const html = `
    <p>You requested a password reset. Click the link below to set a new password (valid for 15 minutes):</p>
    <p><a href="${resetUrl}">${resetUrl}</a></p>
    <p>If you didn't request this, you can ignore this message.</p>
  `;
  await transporter.sendMail({
    from: process.env.EMAIL_FROM,
    to: email,
    subject: "Reset your password",
    html
  });
}

