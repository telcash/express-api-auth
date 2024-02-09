const User = require('./../models/User.model');
const { generateHash, validHash, getTokens, updateRefreshToken } = require('./../auth/auth');

async function register (user) {
    const hashedPassword = await generateHash(user.password);
    const {password, ...newUser} = (await User.create(
        {
            ...user,
            password: hashedPassword,
            role: 'subscriber',
            refreshToken: '',
        }
    )).toObject();
    return newUser;
}

async function login(user) {
    const tokens = getTokens(user);
    await updateRefreshToken(user._id, tokens.refreshToken);
    return tokens;
}

async function logout(user) {
    await updateRefreshToken(user._id);
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
    refreshTokens
}