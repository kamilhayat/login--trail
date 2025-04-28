import { loginUser } from '@/lib/validations/user.action'
import { cookies } from 'next/headers'

export async function POST(req: Request) {
    const { email, password } = await req.json()
    const result = await loginUser({ email, password })
    if (!result.success) {
        return new Response(JSON.stringify({ messsage: result.message }), { status: 400 })
    }
    (await cookies()).set('token', result.token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 60 * 60 * 24 * 7, // 1 week
        path: '/home',
    })
    return new Response(JSON.stringify({ message: 'Login successful' }), { status: 200 });

}