import mongoose from 'mongoose';

let isConnected = false;

export const connectToDB = async () => {

  if (!process.env.MONGODB_URI) {
    console.log('MongoDB URI not found');
    return;
  }

  if (isConnected) {
    console.log('MongoDB is already connected');
    return;
  }

  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      dbName: 'userData',
    });
    isConnected = true;
    console.log('MongoDB connected successfully');
  } catch (err) {
    console.log('MongoDB connection failed', err);
  }
};
