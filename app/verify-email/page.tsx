'use client'; // 👈 VERY IMPORTANT

import { useEffect, useState, Suspense } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';

export default function VerifyEmailPage() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <VerifyEmail />
    </Suspense>
  );
}

function VerifyEmail() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const [message, setMessage] = useState('Verifying your email...');

  useEffect(() => {
    const verifyEmail = async () => {
      const token = searchParams.get('token');
      if (!token) {
        setMessage('No token found!');
        return;
      }

      try {
        const res = await fetch(`/api/verify-email?token=${token}`);
        const data = await res.json();

        if (res.ok) {
          setMessage('Email verified successfully!');
          // Optionally redirect after few seconds
          setTimeout(() => {
            router.push('/login'); // or wherever you want
          }, 3000);
        } else {
          setMessage(data.message || 'Verification failed');
        }
      } catch (error) {
        console.error('Verification error', error);
        setMessage('Something went wrong.');
      }
    };

    verifyEmail();
  }, [searchParams, router]);

  return (
    <div className="flex justify-center items-center h-screen">
      <h1 className="text-2xl font-bold">{message}</h1>
    </div>
  );
}
