// /api/check-user/route.ts
import { connectToDB } from '@/server/mongoose';
import { User } from '@/server/models/User';
import { NextRequest, NextResponse } from 'next/server';

export async function POST(req: NextRequest) {
  await connectToDB();

  try {
    const { identifier } = await req.json();

    const existingUser = await User.findOne({ identifier });

    if (existingUser) {
      return NextResponse.json({ exists: true }, { status: 200 });
    } else {
      return NextResponse.json({ exists: false }, { status: 200 });
    }
  } catch (error) {
    console.error('[CHECK_USER_ERROR]', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
