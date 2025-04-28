import { CreateUser } from '@/lib/validations/user.action';
import { NextRequest, NextResponse } from 'next/server';

export async function POST(req: NextRequest) {
  const { email, username, password } = await req.json();

  // Validate the incoming data
  if (!email || !username || !password) {
    return NextResponse.json(
      { message: 'All fields are required' },
      { status: 400 }
    );
  }

  try {
    // Call the CreateUser function to create a new user
    const createdUser = await CreateUser({ email, username, password });

    // Check if the user creation was successful
    if (createdUser.success) {
      return NextResponse.json(
        { message: 'User created successfully' },
        { status: 201 }
      );
    } else {
      // If something went wrong in CreateUser function
      return NextResponse.json(
        { message: createdUser.message },
        { status: 400 }
      );
    }
  } catch (error) {
    console.error('Error during user creation:', error);
    return NextResponse.json(
      { message: 'Internal server error' },
      { status: 500 }
    );
  }
}
