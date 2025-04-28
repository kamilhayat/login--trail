import User from '@/lib/models/User';
import { connectToDB } from '@/lib/mongoose';

export async function GET(req: Request) {
  try {
    await connectToDB();

    const { searchParams } = new URL(req.url);
    const token = searchParams.get('token');

    if (!token) {
      return new Response(JSON.stringify({ message: 'Token is missing' }), { status: 400 });
    }

    const user = await User.findOne({ verificationToken: token });

    if (!user) {
      return new Response(JSON.stringify({ message: 'Invalid or expired token' }), { status: 400 });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save();

    return new Response(JSON.stringify({ message: 'Email verified successfully' }), { status: 200 });
  } catch (error: any) {
    console.error('Verification error:', error);
    return new Response(JSON.stringify({ message: error.message || 'Server Error' }), { status: 500 });
  }
}
