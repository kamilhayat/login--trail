// server/models/user.ts
import mongoose, { Schema, model, models } from 'mongoose';

const userSchema = new Schema({
  identifier: { type: String, required: true, unique: true }, // email or phone
  name: { type: String, required: true },
  password: { type: String, required: true }, // should be hashed
  createdAt: { type: Date, default: Date.now }
});

export const User = models.User || model('User', userSchema);
