const express = require('express');
const router = express.Router();

const {register, login, logout, authenticateToken, refreshTokens} = require('./../controllers/auth.controller');
const passport = require('passport');

const { validate, credentialsValidations } = require('./../validators/validate');

router.post('/register', validate(credentialsValidations), async (req, res) => {
    try {
        await register(req);
        return res.status(200).send({message: "User registered successfully"});
    } catch {
        return res.status(500).send({message: "Error registering user"});
    }
});

router.post('/login', validate(credentialsValidations), passport.authenticate('local', {session: false}), async (req, res) => {
    try {
        const tokens = await login(req.user);
        res.status(200).json(tokens);
    } catch {
        return res.status(500).send({message: "Login error"});
    }
});

router.get('/logout', authenticateToken, async (req, res) => {
    try {
        await logout(req.user);
        res.status(200).send({message: 'User logged out'});
    } catch {
        return res.status(500).send({message: "Logout error"});
    }
});

router.get('/refresh', authenticateToken, async (req, res) => {
    try {
        const tokens = await refreshTokens(req.user._id, req.refreshToken);
        res.status(200).json(tokens);
    } catch {
        return res.status(500).send({message: "Error refreshing tokens"});
    }
});

module.exports = router;