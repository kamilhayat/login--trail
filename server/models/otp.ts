import mongoose from 'mongoose';

const otpSchema = new mongoose.Schema({
  identifier: { type: String, required: true, unique: true },
  otp: { type: String, required: true },
  expiresAt: { type: Date, required: true }
});

const OTP = mongoose.models.OTP || mongoose.model('OTP', otpSchema);
export { OTP };
