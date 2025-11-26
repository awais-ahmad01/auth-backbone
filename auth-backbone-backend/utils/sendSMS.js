import twilio from "twilio";

const client = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

export async function sendOtpSms(phone, otp) {
  await client.messages.create({
    body: `Your NoteSyncPro login code: ${otp}`,
    from: process.env.TWILIO_PHONE_NUMBER,
    to: phone
  });
}
