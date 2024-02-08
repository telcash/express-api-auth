const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const User = require('./../models/User.model');
const CONFIG = require('./../config/config');

async function generateHash (data) {
    const salt = await bcrypt.genSalt(12);
    return await bcrypt.hash(data, salt);
}

async function validHash(data, hash) {
    return await bcrypt.compare(data, hash);
}

async function register (req) {
    const hashedPassword = await generateHash(req.body.password);
    return await User.create(
        {
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            email: req.body.email,
            password: hashedPassword,
        }
    )
}

async function login(user) {
    const tokens = getTokens(user);
    await updateRefreshToken(user._id, tokens.refreshToken);
    return tokens;
}

async function logout(user) {
    await updateRefreshToken(user._id);
}

function getTokens(user) {
    const payload = {
        _id: user._id,
        role: user.role,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
    }
    const token = jwt.sign(payload, CONFIG.JWT_ACCESS_SECRET, { expiresIn: CONFIG.JWT_ACCESS_EXPIRES_IN});
    const refreshToken = jwt.sign(payload, CONFIG.JWT_REFRESH_SECRET, { expiresIn: CONFIG.JWT_REFRESH_EXPIRES_IN});
    return {token: token, refreshToken: refreshToken};
};

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    if(authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        if (token == null) {
            return res.sendStatus(401);
        }
        const secret = req.originalUrl === '/auth/refresh' ? CONFIG.JWT_REFRESH_SECRET :
            CONFIG.JWT_ACCESS_SECRET;
        jwt.verify(token, secret, (err, user) => {
            if (err) {
                return res.sendStatus(403);
            }
            req.user = user;
            if (req.originalUrl === '/auth/refresh') {
                req.refreshToken = token;
            }
            next();
        });
    } else {
        return res.sendStatus(401);
    }
}

async function updateRefreshToken(userId, refreshToken) {
    if (refreshToken) {
        const hashedRefreshToken = await generateHash(refreshToken);
        await User.updateOne({ _id: userId }, { refreshToken: hashedRefreshToken});
    } else {
        await User.updateOne({ _id: userId }, { refreshToken: ''});
    }
}

async function refreshTokens(userId, refreshToken){
    const user = await User.findOne({_id: userId});
    if(await validHash(refreshToken, user.refreshToken)) {
        const tokens = getTokens(user);
        await updateRefreshToken(userId, tokens.refreshToken);
        return tokens;
    }
}

module.exports = {
    register,
    login,
    logout,
    validHash,
    authenticateToken,
    refreshTokens
}