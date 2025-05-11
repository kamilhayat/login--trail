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
import { toast } from 'react-toastify';
import { useRouter } from 'next/navigation';

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const phoneRegex = /^\d{10}$/;

const loginSchema = z.object({
  identifier: z
    .string()
    .nonempty('Email or phone is required')
    .refine(
      (val) => emailRegex.test(val) || phoneRegex.test(val),
      'Must be a valid email or 10-digit phone number'
    ),
  password: z.string().min(6, 'Password must be at least 6 characters'),
});

type LoginFormData = z.infer<typeof loginSchema>;

export default function LoginPage() {
  const form = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      identifier: '',
      password: '',
    },
  });

  const [isLoggingIn, setIsLoggingIn] = useState(false);

  const router = useRouter();

  const handleLogin = async (data: LoginFormData) => {
    setIsLoggingIn(true);

    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });

      const result = await res.json();

      if (!res.ok) {
        throw new Error(result.error || 'Login failed');
      }

      toast.success('Login successful!');

      if (result.token) {
        localStorage.setItem('token', result.token);
      }

      router.push('/'); // redirect to home/dashboard
    } catch (error: any) {
      toast.error(error.message || 'Something went wrong');
    } finally {
      setIsLoggingIn(false);
    }
  };

  return (
    <div className='max-w-md mx-auto mt-20 p-6 bg-white rounded-2xl shadow-md'>
      <h2 className='text-2xl font-semibold text-center mb-6'>Login</h2>
      <Form {...form}>
        <form onSubmit={form.handleSubmit(handleLogin)} className='space-y-5'>
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
                  <Input type='password' placeholder='••••••••' {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <Button className='w-full' type='submit' disabled={isLoggingIn}>
            {isLoggingIn ? 'Logging in...' : 'Login'}
          </Button>
        </form>
      </Form>
    </div>
  );
}
