'use client';

import { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';

const VerifyEmailPage = () => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const token = searchParams.get('token');

  const [message, setMessage] = useState('Verifying your email...');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const verifyEmail = async () => {
      if (!token) {
        setMessage('Invalid or missing token.');
        setLoading(false);
        return;
      }

      try {
        const res = await fetch(`/api/verify-email?token=${token}`);
        const data = await res.json();

        if (res.ok) {
          setMessage('✅ Email verified successfully! Redirecting to login...');
          setTimeout(() => {
            router.push('/login'); // after successful verification, go to login
          }, 3000);
        } else {
          setMessage(`❌ ${data.message}`);
        }
      } catch (error) {
        setMessage('❌ Something went wrong. Please try again.');
      } finally {
        setLoading(false);
      }
    };

    verifyEmail();
  }, [token, router]);

  return (
    <section className="flex items-center justify-center min-h-screen">
      <div className="text-center">
        <h1 className="text-2xl font-semibold">{message}</h1>
        {loading && <p className="text-gray-500 mt-4">Please wait...</p>}
      </div>
    </section>
  );
};

export default VerifyEmailPage;
