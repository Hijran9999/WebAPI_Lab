const jwt = require('jsonwebtoken');
const User = require('../models/User');

module.exports = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ status: 'error', error: { code: 'INVALID_TOKEN', message: 'Token missing or invalid' } });
    }

    const token = authHeader.split(' ')[1];
    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(payload.sub).select('-passwordHash');
        if (!req.user) throw new Error();
        next();
    } catch (err) {
        return res.status(401).json({ status: 'error', error: { code: 'INVALID_TOKEN', message: 'Token invalid' } });
    }
};
