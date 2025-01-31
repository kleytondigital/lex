const express = require('express');
const router = express.Router();
const authMiddleware = require('../middlewares/auth');
const adminMiddleware = require('../middlewares/admin');

// Debug middleware para todas as rotas
router.use((req, res, next) => {
    console.log('Route accessed:', {
        method: req.method,
        path: req.path,
        fullUrl: req.originalUrl
    });
    next();
});

// Rotas públicas
router.use('/auth', require('./auth'));
router.use('/p', require('./landpage')); // Rota pública para landing pages de clientes
router.use('/c', require('./landpage')); // Rota pública para landing pages de consultores

// Middleware de autenticação para rotas protegidas
router.use((req, res, next) => {
    // Excluir rotas públicas do middleware de autenticação
    if (req.path.startsWith('/p/') || req.path.startsWith('/c/') || req.path.startsWith('/auth/')) {
        return next();
    }
    return authMiddleware(req, res, next);
});

// Rotas protegidas
router.use('/admin', adminMiddleware, require('./admin')); // Rotas de admin
router.use('/user', require('./user')); // Todas as rotas de usuário

// Tratamento de erro 404 para rotas não encontradas
router.use((req, res) => {
    console.log('Rota não encontrada:', req.path);
    res.status(404).json({ message: 'Rota não encontrada' });
});

module.exports = router;