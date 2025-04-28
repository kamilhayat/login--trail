import User from '@/lib/models/User';
import { connectToDB } from '@/lib/mongoose';


export async function get(req: Request) {
    const { searchParams } = new URL(req.url);
    const token= searchParams.get('token');

    if(!token){
        return new Response(JSON.stringify({message: 'Token not found'}), {status: 400})
    }
    await connectToDB()
    const user = await User.findOne({verificationToken: token});
    if(!user){
        return new Response(JSON.stringify({message: 'User not found'}), {status: 400})
    }
    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save()
    return new Response(JSON.stringify({message: 'Email verified successfully'}), {status: 200})
}