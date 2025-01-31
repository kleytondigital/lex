const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const authMiddleware = require('../middlewares/auth');

// Debug middleware
router.use((req, res, next) => {
    console.log('Auth route accessed:', {
        method: req.method,
        path: req.path,
        fullUrl: req.originalUrl,
        body: req.body
    });
    next();
});

// Rotas públicas
router.post('/login', authController.login);
router.post('/register', authController.register);

// Rotas protegidas
router.get('/me', authMiddleware, authController.me);

module.exports = router;