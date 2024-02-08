require('dotenv').config();

module.exports = {
    MONGODB_URL: process.env.MONGODB_URL,
    PORT: process.env.PORT,
    JWT_ACCESS_SECRET: process.env.JWT_ACCESS_SECRET,
    JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET,
    JWT_ACCESS_EXPIRES_IN: parseInt(process.env.JWT_ACCESS_EXPIRES_IN),
    JWT_REFRESH_EXPIRES_IN: parseInt(process.env.JWT_REFRESH_EXPIRES_IN)
}