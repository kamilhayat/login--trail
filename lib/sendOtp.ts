// lib/sendEmail.ts
import nodemailer from 'nodemailer';

export const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

export async function sendEmail(to: string, otp: string) {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to, 
    subject: 'Your OTP for Verification',
    html: `
      <div style="font-family: Arial, sans-serif; line-height: 1.5;">
        <h2>OTP Verification</h2>
        <p>Your one-time password (OTP) is:</p>
        <h3>${otp}</h3>
        <p>This OTP will expire in 10 minutes. Do not share it with anyone.</p>
      </div>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('OTP email sent successfully!');
  } catch (error) {
    console.error('Error sending OTP email:', error);
    throw new Error('Failed to send OTP email');
  }
}
