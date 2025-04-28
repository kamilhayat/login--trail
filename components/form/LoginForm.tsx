'use client';
import React from 'react';
import { useForm } from 'react-hook-form';
import { Form, FormField, FormItem, FormLabel, FormMessage } from '../ui/form';
import { Button } from '../ui/button';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { useRouter } from 'next/navigation';

const formSchema = z.object({
  email: z.string().email({ message: 'Invalid email address' }),
  username: z
    .string()
    .min(3, { message: 'Username must be at least 3 characters long' }),
  password: z
    .string()
    .min(6, { message: 'Password must be at least 6 characters long' }),
});

const LoginForm = () => {
  const router = useRouter();
  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      email: '',
      username: '',
      password: '',
    },
  });

  const onSubmit = async (values: z.infer<typeof formSchema>) => {
    try {
      const res = await fetch('/api/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(values),
      });
      const data = await res.json();
      if (res.ok) {
        console.log('User created successfully', data);
        router.push('/home');
      } else {
        console.log('User creation failed', data);
      }
    } catch (error) {
      console.error('An error occurred:', error);
    }
  };

  return (
    <section className='flex flex-col items-center justify-center h-screen '>
      <h1 className='text-gray-600 text-xl p-4'>SignUp</h1>
      <div>
        <Form {...form}>
          <form
            className='flex flex-col gap-6 bg-white shadow-2xl p-20'
            onSubmit={form.handleSubmit(onSubmit)}
          >
            <FormField
              control={form.control}
              name='email'
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Email</FormLabel>
                  <input
                    {...field}
                    placeholder='Enter your Email'
                    className='border-2 p-4 rounded-md'
                  />
                  <FormMessage />
                </FormItem>
              )}
            ></FormField>
            <FormField
              control={form.control}
              name='username'
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Username</FormLabel>
                  <input
                    {...field}
                    placeholder='Enter your username'
                    className='border-2 p-4 rounded-md'
                  />
                  <FormMessage />
                </FormItem>
              )}
            ></FormField>
            <FormField
              control={form.control}
              name='password'
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Password</FormLabel>
                  <input
                    {...field}
                    placeholder='Enter your password'
                    className='border-2 p-4 rounded-md'
                    type='password'
                  />
                  <FormMessage />
                </FormItem>
              )}
            ></FormField>
            <Button
              type='submit'
              className='bg-blue-500 text-white p-4 rounded-md hover:bg-blue-600'
            >
              Login
            </Button>
          </form>
        </Form>
      </div>
    </section>
  );
};

export default LoginForm;
