const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const UserSchema = new Schema({
    role: {
        type: String,
        enum: ["admin", "subscriber"],
        default: "subscriber",
    },
    firstName: {
        type: String,
    },
    lastName: {
        type: String,
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
    },
    refreshToken: {
        type: String,
    }
});

const User = mongoose.model("User", UserSchema);
module.exports = User;