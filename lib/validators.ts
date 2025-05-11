// lib/validators.ts

export function isEmail(value: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(value);
  }
  
  export function isPhoneNumber(value: string): boolean {
    // Very basic phone validation: 10 to 15 digits, can start with +
    const phoneRegex = /^(\+\d{1,3})?\d{10,15}$/;
    return phoneRegex.test(value);
  }
  