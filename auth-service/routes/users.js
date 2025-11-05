const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const authMiddleware = require('../middleware/auth');

const router = express.Router();

// SIGNUP
router.post('/signup', async (req, res) => {
    const { email, name, password } = req.body;
    if (!email || !name || !password) return res.status(400).json({ status: 'error', error: { code: 'INVALID_INPUT', message: 'Missing fields' } });

    try {
        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            return res.status(400).json({ status: 'error', error: { code: 'DUPLICATE_EMAIL', message: 'Email is already registered' } });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const user = await User.create({ email, name, passwordHash });
        res.status(201).json({ status: 'ok', data: { userId: user._id } });
    } catch (err) {
        res.status(500).json({ status: 'error', error: { code: 'SERVER_ERROR', message: err.message } });
    }
});

// LOGIN
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ status: 'error', error: { code: 'INVALID_INPUT', message: 'Missing fields' } });

    try {
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) return res.status(400).json({ status: 'error', error: { code: 'EMAIL_NOT_FOUND', message: 'Email not found' } });

        const match = await bcrypt.compare(password, user.passwordHash);
        if (!match) return res.status(401).json({ status: 'error', error: { code: 'BAD_PASSWORD', message: 'Wrong password' } });

        const expiresIn = parseInt(process.env.JWT_EXPIRES_IN) || 900;
        const token = jwt.sign({ sub: user._id }, process.env.JWT_SECRET, { expiresIn });

        res.json({
            status: 'ok',
            data: {
                accessToken: token,
                tokenType: 'Bearer',
                expiresIn
            }
        });
    } catch (err) {
        res.status(500).json({ status: 'error', error: { code: 'SERVER_ERROR', message: err.message } });
    }
});

// ME (Protected)
router.get('/me', authMiddleware, async (req, res) => {
    res.json({
        status: 'ok',
        data: { user: { id: req.user._id, email: req.user.email, name: req.user.name, createdAt: req.user.createdAt } }
    });
});

module.exports = router;
