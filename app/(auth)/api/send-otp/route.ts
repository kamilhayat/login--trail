import { storeOtpInDatabase } from '@/lib/generateotp';
import { sendEmail } from '@/lib/sendOtp';
import { connectToDB } from '@/server/mongoose';
import { NextRequest, NextResponse } from 'next/server';

export async function POST(req: NextRequest) {
  await connectToDB()

  try {
    const { identifier } = await req.json();

    // Validate identifier (email or phone) format here if needed

    // Store OTP in the database and get the generated OTP
    const otp = await storeOtpInDatabase(identifier);

    // Send OTP via email or SMS (depending on identifier type)
    await sendEmail(identifier, otp);  // Adjust this based on the type of identifier (email/phone)

    return NextResponse.json({ success: true }, { status: 200 });
  } catch (error) {
    console.error('Error generating OTP:', error);
    return NextResponse.json({ error: 'OTP generation failed. Please try again.' }, { status: 500 });
  }
}
