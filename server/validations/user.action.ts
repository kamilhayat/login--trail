'use server';

import { connectToDB } from '@/server/mongoose';
import bcrypt from 'bcryptjs';
import User from '../models/User';
import { transporter, sendEmail } from '../../lib/nodemailer';
import { sendSms } from '@/lib/sendSms'; // (make sure you have this)
import { isEmail, isPhoneNumber } from '@/lib/validators'; // validation helpers

const JWT_SECRET = process.env.JWT_SECRET;
if (!process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET is not defined in environment variables');
}


interface CreateUserProps {
  contact: string;
  password: string;
}

export const createUser = async ({ contact, password }: CreateUserProps) => {
  try {
    await connectToDB(); // Connect MongoDB

    let email: string | null = null;
    let phone: string | null = null;

    if (isEmail(contact)) {
      email = contact;
    } else if (isPhoneNumber(contact)) {
      phone = contact;
    } else {
      throw new Error('Invalid email or phone number format');
    }

    // Check if user exists by email or phone
    const existingUser = await User.findOne({
      $or: [{ email }, { phone }],
    });

    if (existingUser) {
      throw new Error('User already exists');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // Create new user
    const newUser = await User.create({
      email,
      phone,
      password: hashedPassword,
      otp,
      otpExpiration: Date.now() + 10 * 60 * 1000, // 10 minutes
      isVerified: false,
    });

    // Send OTP via email or SMS
    const otpMessage = `Your OTP is: ${otp}. It will expire in 10 minutes.`;

    if (email) {
      await transporter.sendMail({
        ...sendEmail,
        to: email,
        subject: 'Your OTP for Verification',
        html: `<p>${otpMessage}</p>`,
      });
    } else if (phone) {
      await sendSms(phone, otp);
    }

    return {
      success: true,
      message: 'User created successfully. OTP sent!',
      userId: newUser._id,
    };
  } catch (error: any) {
    console.error('Error creating user:', error.message || error);
    throw new Error(error.message || 'Unable to create user');
  }
};


//otp verifcatin
// OTP Verification function
export async function verifyOtp(email: string, otp: string) {
    try {
        await connectToDB();
        const user = await User.findOne({ email });

        if (!user) {
            throw new Error("User not found");
        }

        // Check if OTP is valid and not expired
        if (user.otp !== otp) {
            throw new Error("Invalid OTP");
        }

        if (Date.now() > user.otpExpiration) {
            throw new Error("OTP has expired");
        }

        // OTP is valid, mark user as verified
        user.isVerified = true;
        user.otp = undefined; // Remove OTP after verification
        user.otpExpiration = undefined; // Remove OTP expiration
        await user.save();

        return {
            success: true,
            message: "Email verified successfully",
        };
    } catch (error: any) {
        console.error("OTP verification error:", error.message || error);
        throw new Error(error.message || "Unable to verify OTP");
    }
}





    // export async function login({ email, password, otp }: { email: string; password: string; otp?: string }) {
    //   try {
    //     if (!email || !password) throw new Error('Please provide email and password');
    
    //     const sanitizedInputs = {
    //       email: sanitizeInput(email),
    //       password: sanitizeInput(password),
    //       otp: otp ? sanitizeInput(otp) : undefined,
    //     };
    
    //     if (email !== sanitizedInputs.email || password !== sanitizedInputs.password) throw new Error('Please provide safe email and password');
    
    //     await connectToDB();
    
    //     const user = await User.findOne({ email }).select('+password +verification');
    
    //     if (!user) throw new Error('Invalid Credentials');
    
    //     const isActive = user.isActive;
    
    //     if (!isActive || isActive !== true) throw new Error('You are banned from accessing the platform');
    
    //     const isMatch = await bcrypt.compare(password, user.password);
    
    //     if (!isMatch) throw new Error('Invalid Credentials');
    
    //     const now = Date.now();
    //     const otpAttempts = user.verification?.otpAttempts || [];
    
    //     if (!otp) {
    //       if (otpAttempts.length >= 5 && now - user.verification.lastAttempt < 300000) {
    //         const remainingTime = 300000 - (now - user.verification.lastAttempt);
    //         const remainingMinutes = Math.floor(remainingTime / 60000);
    //         const remainingSeconds = Math.floor((remainingTime % 60000) / 1000);
    
    //         throw new Error(`You have exceeded the maximum number of OTP attempts. Please try again after ${remainingMinutes} minute${remainingMinutes > 1 ? 's' : ''} and ${remainingSeconds} seconds`);
    //       }
    
    //       const generatedOTP = user.generateOTP();
    //       user.verification.code = generatedOTP;
    //       user.verification.otpAttempts.push(now);
    //       user.verification.lastAttempt = now;
    
    //       await user.save();
    
    //       const loginOtpEmail = renderEmail<IEmailLoginOtp>({
    //         EmailElement: LoginOtpEmail,
    //         props: {
    //           name: user.name,
    //           otp: generatedOTP,
    //           email: user.email,
    //         },
    //       });
    
    //       const loginOtpEmailParams = {
    //         to: email,
    //         subject: 'OTP for login email',
    //         text: `Your login OTP`,
    //         html: loginOtpEmail,
    //       };
    
    //       await sendMail(loginOtpEmailParams);
    //       return { status: StatusCodes.OK, message: 'OTP sent successfully. Please check your email.', otpSent: true };
    //     } else {
    //       const isOTPValid = user.verifyOTP(otp);
    
    //       if (!isOTPValid) throw new Error('Invalid or expired OTP');
    
    //       user.verification.otpAttempts = [];
    //       await user.save();
    //     }
    
    //     const tokenUser = await createTokenUser(user);
    //     const refreshToken = uuidv4();
    
    //     attachCookiesToResponse({ user: tokenUser, refreshToken });
    
    //     return JSON.parse(JSON.stringify({ ...tokenUser }));
    //   } catch (error: any) {
    //     console.error(error.message);
    //     return traceErrors(error);
    //   }
    // }
    
    // export const logout = async () => {
    //   cookies().delete('accessToken');
    //   cookies().delete('refreshToken');
    
    //   return {
    //     status: StatusCodes.OK,
    //     message: 'Logged out successfully',
    //   };
    // };
    // export async function forgotPassword({ email }: { email: string }) {
    //   try {
    //     if (!email) throw new Error('Please provide an email address');
    
    //     const sanitizedEmail = sanitizeInput(email);
    
    //     if (email !== sanitizedEmail) throw new Error('Please provide a valid email address');
    
    //     await connectToDB();
    
    //     const user = await User.findOne({ email: sanitizedEmail });
    
    //     if (!user) throw new Error('No accounts found with the credentials provided.');
    
    //     const passwordResetToken = uuidv4();
    //     const hashedToken = await bcrypt.hash(passwordResetToken, 10);
    
    //     const tenMinutes = new Date(Date.now() + 10 * 60 * 1000);
    
    //     user.passwordReset = { token: hashedToken, expiry: tenMinutes };
    
    //     await user.save();
    
    //     const forgotPasswordHtml = renderEmail<IPasswordResetEmail>({
    //       EmailElement: PasswordResetEmail,
    //       props: {
    //         name: user.name,
    //         resetToken: passwordResetToken,
    //         email: 'cyberbizztechnologies@gmail.com',
    //       },
    //     });
    
    //     const forgotPasswordParams = {
    //       to: email,
    //       subject: 'Password Reset Email',
    //       text: `Your password reset email`,
    //       html: forgotPasswordHtml,
    //     };
    
    //     await sendMail(forgotPasswordParams);
    //     return {
    //       status: StatusCodes.OK,
    //       message: 'Please check your email',
    //     };
    //   } catch (error) {
    //     console.error('Error in forgotPassword:', error);
    //     return traceErrors(error);
    //   }
    // }
    
    // export async function resetPassword({ newPassword, confirmPassword, token, email }: { newPassword: string; confirmPassword: string; token: string; email: string }) {
    //   try {
    //     if (newPassword !== confirmPassword) throw new Error('Passwords should match');
    
    //     const sanitizedEmail = sanitizeInput(email);
    //     if (email !== sanitizedEmail) throw new Error('Please provide a valid email address');
    
    //     await connectToDB();
    
    //     const user = await getUserForReset({ field: 'email', value: email, resetMode: true });
    
    //     if (!user) throw new Error('No user found with the given details');
    
    //     const isValidResetSession = await validateResetToken({ token, user });
    
    //     if (!isValidResetSession) throw new Error('Something went wrong, please try again later.');
    
    //     const updateUser = await User.findById(user._id);
    
    //     updateUser.password = newPassword;
    //     updateUser.passwordReset = { token: undefined, expiry: undefined };
    //     await updateUser.save();
    
    //     return {
    //       status: StatusCodes.OK,
    //       message: 'Your password was changed.',
    //     };
    //   } catch (error) {
    //     console.error('Error in resetPassword:', error);
    //     return traceErrors(error);
    //   }
    // }
    
    // export const validateResetToken = async ({ token, user }: { token: string; user: UserDocument }) => {
    //   const currentDate = new Date();
    
    //   if (!user.passwordReset?.expiry || !user.passwordReset?.token) throw new Error('Please provide token and expiry');
    
    //   const isTokenValid = await bcrypt.compare(token, user.passwordReset.token);
    
    //   if (!isTokenValid) throw new Error('Token is invalid');
    
    //   if (user.passwordReset.expiry < currentDate) throw new Error('Token expired');
    
    //   return isTokenValid;
    // };
    
    // export async function getAllUsers() {
    //   try {
    //     await connectToDB();
    
    //     const allUsers: UserDocument[] = await User.find().sort({
    //       createdAt: 'desc',
    //     });
    
    //     return JSON.parse(JSON.stringify(allUsers));
    //   } catch (error) {
    //     console.error('Error fetching all users:', error);
    //     return traceErrors(error);
    //   }
    // }
    
    // export async function getUserById(userId: string) {
    //   try {
    //     await connectToDB();
    
    //     const user: UserDocument | any = await User.findById(userId).lean();
    
    //     return user;
    //   } catch (error: any) {
    //     console.error('Error fetching user:', error.message);
    //     return traceErrors(error);
    //   }
    // }
    
    // export async function getUserForReset({ field, value, resetMode = false }: { field: keyof UserDocument; value: any; resetMode?: boolean }) {
    //   try {
    //     await connectToDB();
    
    //     const matchStage = { $match: { [field]: value } };
    
    //     const projectionStage = {
    //       $project: {
    //         name: 1,
    //         email: 1,
    //         role: 1,
    //         isActive: 1,
    //         createdAt: 1,
    //         updatedAt: 1,
    //         passwordReset: resetMode ? 1 : undefined,
    //       },
    //     };
    
    //     const pipeline = [matchStage, projectionStage];
    
    //     const [user] = await User.aggregate(pipeline);
    
    //     return user;
    //   } catch (error) {
    //     console.error(`Error fetching user by ${field}:`, error);
    //     return traceErrors(error);
    //   }
    // }
    
    // export async function updateUserById({ userId, name, email, password, role }: { userId: string | ObjectId } & IUser) {
    //   try {
    //     await connectToDB();
    
    //     const user = await User.findById(userId);
    
    //     if (!user) {
    //       return {
    //         status: StatusCodes.NOT_FOUND,
    //         message: 'No user found with the specified ID.',
    //       };
    //     }
    
    //     if (name) user.name = name;
    //     if (email) user.email = email;
    //     if (password) user.password = password;
    //     if (role) user.role = role;
    
    //     await user.save();
    
    //     return { status: StatusCodes.OK, message: 'User updated successfully' };
    //   } catch (error) {
    //     console.error('Error updating user:', error);
    //     return traceErrors(error);
    //   }
    // }
    
    // export async function updateUserStatus(userId: string | ObjectId, newStatus: boolean) {
    //   return await handleUpdateStatus(User, userId, newStatus);
    // }
    
    // export async function deleteUserById(userId: string) {
    //   return await handleDeleteById(User, userId);
    // }
    
    // export async function deleteManyUsersById(userIds: string[]) {
    //   return await handleDeleteManyItems(User, userIds);
    // }
    
    // // AUTH
    
    // export const getTokenUser = async ({ accessToken, refreshToken }: { accessToken: string | any; refreshToken: string | any }) => {
    //   const accessTokenUser = accessToken && (await isTokenValid(accessToken));
    //   const refreshTokenUser = refreshToken && (await isTokenValid(refreshToken));
    
    //   const user = accessToken ? accessTokenUser?.payload?.user : refreshToken ? refreshTokenUser?.payload?.user : {};
    
    //   return user;
    // };
    
    // export const createTokenUser = async (user: any): Promise<ITokenUser> => {
    //   return {
    //     name: user.name,
    //     userId: user._id,
    //     role: user.role,
    //     isActive: user.isActive,
    //   };
    // };
    
    // const secretKey = process.env.JWT_SECRET!;
    // const key = new TextEncoder().encode(secretKey);
    
    // export async function createToken(payload: any) {
    //   const token = await new SignJWT(payload).setProtectedHeader({ alg: 'HS256' }).setIssuedAt().sign(key);
    
    //   return token;
    // }
    
    // export async function isTokenValid(token: string): Promise<any> {
    //   const { payload } = await jwtVerify(token, key, { algorithms: ['HS256'] });
    
    //   return payload;
    // }
    
    // export const attachCookiesToResponse = async ({ user, refreshToken }: any) => {
    //   const accessTokenJWT = await createToken({ payload: { user } });
    //   const refreshTokenJWT = await createToken({
    //     payload: { user, refreshToken },
    //   });
    
    //   cookies().set('accessToken', accessTokenJWT, {
    //     httpOnly: true,
    //     secure: process.env.NODE_ENV === 'production',
    //     expires: Date.now() + Number(process.env.ACCESS_TOKEN_AGE),
    //     sameSite: 'strict',
    //   });
    
    //   cookies().set('refreshToken', refreshTokenJWT, {
    //     httpOnly: true,
    //     secure: process.env.NODE_ENV === 'production',
    //     expires: Date.now() + Number(process.env.REFRESH_TOKEN_AGE),
    //     sameSite: 'strict',
    //   });
    // };
    
    // vvvvimport { connectToDB } from '@/database/mongoose';
    // import User, { IUser, UserDocument } from '@/database/models/user.model';
    // import { sanitizeInput, traceErrors } from '@/lib/utils';
    // import { handleDeleteById, handleDeleteManyItems, handleUpdateStatus } from './factory.actions';
    // import { StatusCodes } from '@/constants/StatusCodes';
    // import { IEmailLoginOtp, IPasswordResetEmail } from '@/types';
    // import { PasswordResetEmail, renderEmail } from '@/emails';
    // import { sendMail } from '../utils';
    // import LoginOtpEmail from '@/emails/EmailLoginOtp';
    
    // export interface ITokenUser {
    //   name: string;
    //   userId: string;
    //   role: string;
    //   isActive: boolean;
    // }
    
    // export async function createUser({ name, email, password, role }: IUser) {
    //   try {
    //     await connectToDB();
    
    //     await User.create({ name, email, password, role });
    
    //     return {
    //       status: StatusCodes.CREATED,
    //       message: 'Account created successfully',
    //     };
    //   } catch (error) {
    //     console.error('Error creating user:', error);
    //     return traceErrors(error);
    //   }
    // }
    
    // export async function login({ email, password, otp }: { email: string; password: string; otp?: string }) {
    //   try {
    //     if (!email || !password) throw new Error('Please provide email and password');
    
    //     const sanitizedInputs = {
    //       email: sanitizeInput(email),
    //       password: sanitizeInput(password),
    //       otp: otp ? sanitizeInput(otp) : undefined,
    //     };
    
    //     if (email !== sanitizedInputs.email || password !== sanitizedInputs.password) throw new Error('Please provide safe email and password');
    
    //     await connectToDB();
    
    //     const user = await User.findOne({ email }).select('+password +verification');
    
    //     if (!user) throw new Error('Invalid Credentials');
    
    //     const isActive = user.isActive;
    
    //     if (!isActive || isActive !== true) throw new Error('You are banned from accessing the platform');
    
    //     const isMatch = await bcrypt.compare(password, user.password);
    
    //     if (!isMatch) throw new Error('Invalid Credentials');
    
    //     const now = Date.now();
    //     const otpAttempts = user.verification?.otpAttempts || [];
    
    //     if (!otp) {
    //       if (otpAttempts.length >= 5 && now - user.verification.lastAttempt < 300000) {
    //         const remainingTime = 300000 - (now - user.verification.lastAttempt);
    //         const remainingMinutes = Math.floor(remainingTime / 60000);
    //         const remainingSeconds = Math.floor((remainingTime % 60000) / 1000);
    
    //         throw new Error(`You have exceeded the maximum number of OTP attempts. Please try again after ${remainingMinutes} minute${remainingMinutes > 1 ? 's' : ''} and ${remainingSeconds} seconds`);
    //       }
    
    //       const generatedOTP = user.generateOTP();
    //       user.verification.code = generatedOTP;
    //       user.verification.otpAttempts.push(now);
    //       user.verification.lastAttempt = now;
    
    //       await user.save();
    
    //       const loginOtpEmail = renderEmail<IEmailLoginOtp>({
    //         EmailElement: LoginOtpEmail,
    //         props: {
    //           name: user.name,
    //           otp: generatedOTP,
    //           email: user.email,
    //         },
    //       });
    
    //       const loginOtpEmailParams = {
    //         to: email,
    //         subject: 'OTP for login email',
    //         text: `Your login OTP`,
    //         html: loginOtpEmail,
    //       };
    
    //       await sendMail(loginOtpEmailParams);
    //       return { status: StatusCodes.OK, message: 'OTP sent successfully. Please check your email.', otpSent: true };
    //     } else {
    //       const isOTPValid = user.verifyOTP(otp);
    
    //       if (!isOTPValid) throw new Error('Invalid or expired OTP');
    
    //       user.verification.otpAttempts = [];
    //       await user.save();
    //     }
    
    //     const tokenUser = await createTokenUser(user);
    //     const refreshToken = uuidv4();
    
    //     attachCookiesToResponse({ user: tokenUser, refreshToken });
    
    //     return JSON.parse(JSON.stringify({ ...tokenUser }));
    //   } catch (error: any) {
    //     console.error(error.message);
    //     return traceErrors(error);
    //   }
    // }
    
    // export const logout = async () => {
    //   cookies().delete('accessToken');
    //   cookies().delete('refreshToken');
    
    //   return {
    //     status: StatusCodes.OK,
    //     message: 'Logged out successfully',
    //   };
    // };
    // export async function forgotPassword({ email }: { email: string }) {
    //   try {
    //     if (!email) throw new Error('Please provide an email address');
    
    //     const sanitizedEmail = sanitizeInput(email);
    
    //     if (email !== sanitizedEmail) throw new Error('Please provide a valid email address');
    
    //     await connectToDB();
    
    //     const user = await User.findOne({ email: sanitizedEmail });
    
    //     if (!user) throw new Error('No accounts found with the credentials provided.');
    
    //     const passwordResetToken = uuidv4();
    //     const hashedToken = await bcrypt.hash(passwordResetToken, 10);
    
    //     const tenMinutes = new Date(Date.now() + 10 * 60 * 1000);
    
    //     user.passwordReset = { token: hashedToken, expiry: tenMinutes };
    
    //     await user.save();
    
    //     const forgotPasswordHtml = renderEmail<IPasswordResetEmail>({
    //       EmailElement: PasswordResetEmail,
    //       props: {
    //         name: user.name,
    //         resetToken: passwordResetToken,
    //         email: 'cyberbizztechnologies@gmail.com',
    //       },
    //     });
    
    //     const forgotPasswordParams = {
    //       to: email,
    //       subject: 'Password Reset Email',
    //       text: `Your password reset email`,
    //       html: forgotPasswordHtml,
    //     };
    
    //     await sendMail(forgotPasswordParams);
    //     return {
    //       status: StatusCodes.OK,
    //       message: 'Please check your email',
    //     };
    //   } catch (error) {
    //     console.error('Error in forgotPassword:', error);
    //     return traceErrors(error);
    //   }
    // }
    
    // export async function resetPassword({ newPassword, confirmPassword, token, email }: { newPassword: string; confirmPassword: string; token: string; email: string }) {
    //   try {
    //     if (newPassword !== confirmPassword) throw new Error('Passwords should match');
    
    //     const sanitizedEmail = sanitizeInput(email);
    //     if (email !== sanitizedEmail) throw new Error('Please provide a valid email address');
    
    //     await connectToDB();
    
    //     const user = await getUserForReset({ field: 'email', value: email, resetMode: true });
    
    //     if (!user) throw new Error('No user found with the given details');
    
    //     const isValidResetSession = await validateResetToken({ token, user });
    
    //     if (!isValidResetSession) throw new Error('Something went wrong, please try again later.');
    
    //     const updateUser = await User.findById(user._id);
    
    //     updateUser.password = newPassword;
    //     updateUser.passwordReset = { token: undefined, expiry: undefined };
    //     await updateUser.save();
    
    //     return {
    //       status: StatusCodes.OK,
    //       message: 'Your password was changed.',
    //     };
    //   } catch (error) {
    //     console.error('Error in resetPassword:', error);
    //     return traceErrors(error);
    //   }
    // }
    
    // export const validateResetToken = async ({ token, user }: { token: string; user: UserDocument }) => {
    //   const currentDate = new Date();
    
    //   if (!user.passwordReset?.expiry || !user.passwordReset?.token) throw new Error('Please provide token and expiry');
    
    //   const isTokenValid = await bcrypt.compare(token, user.passwordReset.token);
    
    //   if (!isTokenValid) throw new Error('Token is invalid');
    
    //   if (user.passwordReset.expiry < currentDate) throw new Error('Token expired');
    
    //   return isTokenValid;
    // };
    
    // export async function getAllUsers() {
    //   try {
    //     await connectToDB();
    
    //     const allUsers: UserDocument[] = await User.find().sort({
    //       createdAt: 'desc',
    //     });
    
    //     return JSON.parse(JSON.stringify(allUsers));
    //   } catch (error) {
    //     console.error('Error fetching all users:', error);
    //     return traceErrors(error);
    //   }
    // }
    
    // export async function getUserById(userId: string) {
    //   try {
    //     await connectToDB();
    
    //     const user: UserDocument | any = await User.findById(userId).lean();
    
    //     return user;
    //   } catch (error: any) {
    //     console.error('Error fetching user:', error.message);
    //     return traceErrors(error);
    //   }
    // }
    
    // export async function getUserForReset({ field, value, resetMode = false }: { field: keyof UserDocument; value: any; resetMode?: boolean }) {
    //   try {
    //     await connectToDB();
    
    //     const matchStage = { $match: { [field]: value } };
    
    //     const projectionStage = {
    //       $project: {
    //         name: 1,
    //         email: 1,
    //         role: 1,
    //         isActive: 1,
    //         createdAt: 1,
    //         updatedAt: 1,
    //         passwordReset: resetMode ? 1 : undefined,
    //       },
    //     };
    
    //     const pipeline = [matchStage, projectionStage];
    
    //     const [user] = await User.aggregate(pipeline);
    
    //     return user;
    //   } catch (error) {
    //     console.error(`Error fetching user by ${field}:`, error);
    //     return traceErrors(error);
    //   }
    // }
    
    // export async function updateUserById({ userId, name, email, password, role }: { userId: string | ObjectId } & IUser) {
    //   try {
    //     await connectToDB();
    
    //     const user = await User.findById(userId);
    
    //     if (!user) {
    //       return {
    //         status: StatusCodes.NOT_FOUND,
    //         message: 'No user found with the specified ID.',
    //       };
    //     }
    
    //     if (name) user.name = name;
    //     if (email) user.email = email;
    //     if (password) user.password = password;
    //     if (role) user.role = role;
    
    //     await user.save();
    
    //     return { status: StatusCodes.OK, message: 'User updated successfully' };
    //   } catch (error) {
    //     console.error('Error updating user:', error);
    //     return traceErrors(error);
    //   }
    // }
    
    // export async function updateUserStatus(userId: string | ObjectId, newStatus: boolean) {
    //   return await handleUpdateStatus(User, userId, newStatus);
    // }
    
    // export async function deleteUserById(userId: string) {
    //   return await handleDeleteById(User, userId);
    // }
    
    // export async function deleteManyUsersById(userIds: string[]) {
    //   return await handleDeleteManyItems(User, userIds);
    // }
    
    // // AUTH
    
    // export const getTokenUser = async ({ accessToken, refreshToken }: { accessToken: string | any; refreshToken: string | any }) => {
    //   const accessTokenUser = accessToken && (await isTokenValid(accessToken));
    //   const refreshTokenUser = refreshToken && (await isTokenValid(refreshToken));
    
    //   const user = accessToken ? accessTokenUser?.payload?.user : refreshToken ? refreshTokenUser?.payload?.user : {};
    
    //   return user;
    // };
    
    // export const createTokenUser = async (user: any): Promise<ITokenUser> => {
    //   return {
    //     name: user.name,
    //     userId: user._id,
    //     role: user.role,
    //     isActive: user.isActive,
    //   };
    // };
    
    // const secretKey = process.env.JWT_SECRET!;
    // const key = new TextEncoder().encode(secretKey);
    
    // export async function createToken(payload: any) {
    //   const token = await new SignJWT(payload).setProtectedHeader({ alg: 'HS256' }).setIssuedAt().sign(key);
    
    //   return token;
    // }
    
    // export async function isTokenValid(token: string): Promise<any> {
    //   const { payload } = await jwtVerify(token, key, { algorithms: ['HS256'] });
    
    //   return payload;
    // }
    
    // export const attachCookiesToResponse = async ({ user, refreshToken }: any) => {
    //   const accessTokenJWT = await createToken({ payload: { user } });
    //   const refreshTokenJWT = await createToken({
    //     payload: { user, refreshToken },
    //   });
    
    //   cookies().set('accessToken', accessTokenJWT, {
    //     httpOnly: true,
    //     secure: process.env.NODE_ENV === 'production',
    //     expires: Date.now() + Number(process.env.ACCESS_TOKEN_AGE),
    //     sameSite: 'strict',
    //   });
    
    //   cookies().set('refreshToken', refreshTokenJWT, {
    //     httpOnly: true,
    //     secure: process.env.NODE_ENV === 'production',
    //     expires: Date.now() + Number(process.env.REFRESH_TOKEN_AGE),
    //     sameSite: 'strict',
    //   });
    // };
    
    
    
    
    
    // export async function createUser({ name, email, password, role }: IUser) {
    //   try {
    //     await connectToDB();
    
    //     await User.create({ name, email, password, role });
    
    //     return {
    //       status: StatusCodes.CREATED,
    //       message: 'Account created successfully',
    //     };
    //   } catch (error) {
    //     console.error('Error creating user:', error);
    //     return traceErrors(error);
    //   }
    // }