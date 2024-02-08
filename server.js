const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('./models/User.model');
const CONFIG = require('./config/config');
const connectToDB = require('./db/db');
const authRoutes = require('./routes/auth.router');
const { validHash } = require('./controllers/auth.controller'); 

const app = express();

app.use(express.json());
app.use(express.urlencoded({extended: true}));

connectToDB();

passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
}, async (email, password, done) => {
    try {
        const user = await User.findOne({ email: email });
        if(!user) {
            return done(null, false, { message: 'Incorrect email or password'})
        }
        if(! await validHash(password, user.password)) {
            return done(null, false, { message: 'Incorrect email or password'})
        }
        return done(null, user)
    } catch (err) {
        return done(err);
    }
}));

app.use('/auth', authRoutes);

app.listen(CONFIG.PORT, () => {
    console.log(`Server is running on port ${CONFIG.PORT}`);
});