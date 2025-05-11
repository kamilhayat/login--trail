'use client';

import { useState } from 'react';
import { z } from 'zod';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import {
  Form,
  FormField,
  FormItem,
  FormLabel,
  FormControl,
  FormMessage,
} from '@/components/ui/form';
import { OTPInputForm } from './InputOtpForm';
import { toast } from 'react-toastify';
import { useRouter } from 'next/navigation';

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const phoneRegex = /^\d{10}$/;

const signupSchema = z.object({
  identifier: z
    .string()
    .nonempty('Email or phone is required')
    .refine(
      (val) => emailRegex.test(val) || phoneRegex.test(val),
      'Must be a valid email or 10-digit phone number'
    ),
  name: z.string().min(2, 'Name is too short'),
  password: z.string().min(6, 'Password must be at least 6 characters'),
});

type SignupFormData = z.infer<typeof signupSchema>;

export default function SignupPage() {
  const [otpRequested, setOtpRequested] = useState(false);
  const [otp, setOtp] = useState('');
  const [isVerifying, setIsVerifying] = useState(false);
  const [isSending, setIsSending] = useState(false);
  const [resendCooldown, setResendCooldown] = useState(0);
  const [isOtpVerified, setIsOtpVerified] = useState(false);

  const router = useRouter();

  const form = useForm<SignupFormData>({
    resolver: zodResolver(signupSchema),
    defaultValues: {
      identifier: '',
      name: '',
      password: '',
    },
  });

  const checkIfUserExists = async (identifier: string) => {
    try {
      const res = await fetch('/api/check-user', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier }),
      });

      const result = await res.json();

      if (!res.ok) {
        toast.error(result.error || 'Failed to check user.');
        return false;
      }

      if (result.exists) {
        toast.error('User already registered with this email or phone.');
        return true;
      }

      return false;
    } catch (err) {
      toast.error('Something went wrong while checking user.');
      return false;
    }
  };

  const sendOtp = async (data: SignupFormData) => {
    const userExists = await checkIfUserExists(data.identifier);
    if (userExists) return;
    setIsSending(true);
    try {
      const res = await fetch('/api/send-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier: data.identifier }),
      });

      const result = await res.json();

      if (!res.ok) throw new Error(result.error || 'OTP failed');

      toast.success('OTP sent to your email');
      setOtpRequested(true);
      setResendCooldown(30);
      const interval = setInterval(() => {
        setResendCooldown((prev) => {
          if (prev === 1) {
            clearInterval(interval);
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
    } catch (err) {
      if (err instanceof Error) {
        toast.error(err.message);
      } else {
        toast.error('Something went wrong');
      }
    } finally {
      setIsSending(false);
    }
  };

  const verifyOtpAndRegister = async (data: SignupFormData) => {
    setIsVerifying(true);
    try {
      const res = await fetch('/api/verify-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identifier: data.identifier,
          name: data.name,
          password: data.password,
          otp,
        }),
      });
      const result = await res.json();

      if (!res.ok) {
        toast.error(result.error || 'OTP verification failed');
      } else {
        toast.success('User registered successfully!');
        if (result.token) {
          localStorage.setItem('token', result.token);
        }
        setIsOtpVerified(true);
        form.reset();
        router.push('/');
      }
    } catch (error) {
      toast.error('Something went wrong');
    } finally {
      setIsVerifying(false);
    }
  };

  const onSubmit = (data: SignupFormData) => {
    sendOtp(data);
  };

  return (
    <div className='max-w-md mx-auto mt-20 p-6 bg-white rounded-2xl shadow-md'>
      <h2 className='text-2xl font-semibold text-center mb-6'>
        Create Account
      </h2>
      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className='space-y-5'>
          <FormField
            control={form.control}
            name='identifier'
            render={({ field }) => (
              <FormItem>
                <FormLabel>Email or Mobile</FormLabel>
                <FormControl>
                  <Input
                    placeholder='example@email.com or 9876543210'
                    {...field}
                    disabled={otpRequested}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name='name'
            render={({ field }) => (
              <FormItem>
                <FormLabel>Full Name</FormLabel>
                <FormControl>
                  <Input
                    placeholder='John Doe'
                    {...field}
                    disabled={otpRequested}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name='password'
            render={({ field }) => (
              <FormItem>
                <FormLabel>Password</FormLabel>
                <FormControl>
                  <Input
                    type='password'
                    placeholder='••••••••'
                    {...field}
                    disabled={otpRequested}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          {!otpRequested ? (
            <Button
              className='w-full cursor-pointer'
              type='submit'
              disabled={isSending}
            >
              {isSending ? 'Sending...' : 'Send OTP'}
            </Button>
          ) : (
            <>
              <div className='space-y-2'>
                <OTPInputForm otp={otp} setOtp={setOtp} />
                <Button
                  className='w-full'
                  type='button'
                  onClick={() => sendOtp(form.getValues())}
                  disabled={resendCooldown > 0 || isSending}
                  variant='outline'
                >
                  {resendCooldown > 0
                    ? `Resend OTP in ${resendCooldown}s`
                    : 'Resend OTP'}
                </Button>
              </div>
              <Button
                className='w-full mt-3 cursor-pointer'
                type='button'
                onClick={form.handleSubmit(verifyOtpAndRegister)}
                disabled={isVerifying}
              >
                {isVerifying ? 'Verifying...' : 'Verify OTP & Signup'}
              </Button>
            </>
          )}
        </form>
      </Form>
    </div>
  );
}
