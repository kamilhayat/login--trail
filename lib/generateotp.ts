
import { OTP } from '@/server/models/otp';
import crypto from 'crypto';

const generateOtp = () => {
  return crypto.randomBytes(3).toString('hex'); 
};

export const storeOtpInDatabase = async (identifier: string) => {
  try {
    const otp = generateOtp();
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + 5); 

    const existingOtp = await OTP.findOne({ identifier });

    if (existingOtp) {
      existingOtp.otp = otp;
      existingOtp.expiresAt = expiresAt;
      await existingOtp.save();
    } else {
      await OTP.create({ identifier, otp, expiresAt });
    }

    return otp;
  } catch (error) {
    throw new Error('Failed to store OTP in database');
  }
};
