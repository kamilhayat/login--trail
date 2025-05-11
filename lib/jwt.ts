import jwt, { SignOptions } from 'jsonwebtoken';

const secret = process.env.JWT_SECRET;
if (!secret) {
  throw new Error('JWT_SECRET is not defined');
}
const JWT_SECRET: string = secret;

interface JWTPayload {
  id: string;
  identifier: string;
}

const SEVEN_DAYS_IN_SECONDS = 7 * 24 * 60 * 60; // 604800

export function createJWT(payload: JWTPayload, expiresIn: number = SEVEN_DAYS_IN_SECONDS): string {
  const options: SignOptions = { expiresIn };
  return jwt.sign(payload, JWT_SECRET, options);
}

export function verifyJWT(token: string): JWTPayload {
  return jwt.verify(token, JWT_SECRET) as JWTPayload;
}
