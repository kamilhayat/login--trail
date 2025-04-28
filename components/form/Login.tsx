'use client';
import { zodResolver } from '@hookform/resolvers/zod';
import React from 'react';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { Form, FormField, FormItem, FormLabel, FormMessage } from '../ui/form';
import { Button } from '../ui/button';
import Router from 'next/router';
import { useRouter } from 'next/navigation';

const formSchema = z.object({
  email: z.string().email({ message: 'Invalid email address' }),
  password: z.string().min(6, { message: 'Invaild passowrd' }),
});
const LoginPage = () => {
  const router = useRouter();
  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      email: '',
      password: '',
    },
  });

  const onSubmit = async (values: z.infer<typeof formSchema>) => {
    try {
      const res = await fetch('api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(values),
      });
      const data = await res.json();
      if (res.ok) {
        console.log('Login Success', data);
        router.push('/home');
      } else {
        console.error('Login Failed', data.message);
        alert(data.message || 'Login failed');
      }
    } catch (error) {
      console.error('An error occurred:', error);
      alert('Something went wrong');
    }
  };
  return (
    <section className='flex flex-col items-center justify-center h-screen '>
      <Form {...form}>
        <form
          onSubmit={form.handleSubmit(onSubmit)}
          className='flex flex-col gap-6 bg-white shadow-2xl p-20'
        >
          <FormField
            control={form.control}
            name='email'
            render={({ field }) => (
              <FormItem>
                <FormLabel>Email</FormLabel>
                <input
                  {...field}
                  type='email'
                  placeholder='Enter your email'
                  className='border-2 p-4 rounded-md'
                />
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
          <Button>
            Forgot Password?
          </Button>
          
        </form>
      </Form>
    </section>
  );
};

export default LoginPage;
