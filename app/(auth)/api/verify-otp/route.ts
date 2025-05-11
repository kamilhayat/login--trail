import { OTP } from '@/server/models/otp';
import { connectToDB } from '@/server/mongoose';
import { NextRequest, NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';
import { createJWT } from '@/lib/jwt';
import { User } from '@/server/models/User';

export async function POST(req: NextRequest) {
  await connectToDB();

  try {
    const { identifier, otp, name, password } = await req.json();

    // 1. Ensure identifier is not null or empty
    if (!identifier || typeof identifier !== 'string' || identifier.trim() === '') {
      return NextResponse.json({ error: 'Identifier (email or phone) is required' }, { status: 400 });
    }
    

    // 2. Check if OTP is valid
    const storedOtp = await OTP.findOne({ identifier });
    if (!storedOtp || storedOtp.otp !== otp) {
      return NextResponse.json({ error: 'Invalid OTP' }, { status: 400 });
    }

    // 3. Check if OTP has expired
    const currentTime = new Date();
    if (storedOtp.expiresAt < currentTime) {
      return NextResponse.json({ error: 'OTP has expired' }, { status: 400 });
    }

    // 4. Clean up OTP
    await OTP.deleteOne({ identifier });

    // 5. Check if user already exists with the same identifier
    const existingUser = await User.findOne({ identifier });
    if (existingUser) {
      return NextResponse.json({ error: 'User already exists' }, { status: 409 });
    }

    // 6. Hash password and create new user
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({ identifier, name, password: hashedPassword });

    // 7. Generate JWT
    const token = createJWT({ id: newUser._id, identifier: newUser.identifier });
    console.log("JWT Token:", token);

    return NextResponse.json({ success: true, token }, { status: 200 });

  } catch (error) {
    console.error('[VERIFY_OTP_ERROR]', error);
    return NextResponse.json({ error: 'OTP verification failed' }, { status: 500 });
  }
}
