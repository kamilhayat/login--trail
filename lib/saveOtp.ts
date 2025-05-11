const otpMap = new Map<string, string>(); // key = identifier, value = otp

export const saveOtp = (identifier: string, otp: string) => {
    otpMap.set(identifier, otp);
    setTimeout(() => otpMap.delete(identifier), 5 * 60 * 1000);
};

export const getOtp = (identifier: string) => otpMap.get(identifier);

export const deleteOtp = (identifier: string) => otpMap.delete(identifier);
