const bcrypt = require('bcrypt');
const CONFIG = require('./../config/config');
const jwt = require('jsonwebtoken');
const User = require('./../models/User.model');

async function generateHash (data) {
    const salt = await bcrypt.genSalt(12);
    return await bcrypt.hash(data, salt);
}

async function validHash(data, hash) {
    return await bcrypt.compare(data, hash);
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

function verifyAdminRole(req, res, next) {
    const userRole = req.user.role;
    if( userRole && userRole === 'admin') {
        next();
    } else {
        return res.status(403).send('Forbidden');
    }
}

function verifyUserId(req, res, next) {
    const id = req.params.id;
    const userId = req.user._id;
    const userRole = req.user.role;
    if( id === userId || userRole === 'admin') {
        next();
    } else {
        return res.status(403).send('Forbidden');
    }
} 

module.exports = {
    generateHash,
    validHash,
    getTokens,
    authenticateToken,
    updateRefreshToken,
    verifyAdminRole,
    verifyUserId
}