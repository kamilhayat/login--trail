import { model, models, Schema } from 'mongoose';


const UserSchema = new Schema({
    email: {
        type: String,
        required: true,
        unique: true,
    },
    username: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
    },
    isVerified: {
        type: Boolean,
        default: false,
    },
    verificationToken: {
        type: String,
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
})

const User = models.user || model('user', UserSchema);
export default User;