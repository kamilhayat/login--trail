"use client";

import {
  InputOTP,
  InputOTPGroup,
  InputOTPSlot,
} from "@/components/ui/input-otp";

interface OTPInputFormProps {
  otp: string;
  setOtp: (otp: string) => void;
}

export function OTPInputForm({ otp, setOtp }: OTPInputFormProps) {
  return (
    <div className="space-y-2">
      <label className="text-sm font-medium">Enter OTP</label>
      <InputOTP maxLength={6} value={otp} onChange={setOtp}>
        <InputOTPGroup>
          {[...Array(6)].map((_, i) => (
            <InputOTPSlot key={i} index={i} />
          ))}
        </InputOTPGroup>
      </InputOTP>
    </div>
  );
}
