const express = require('express');
const router = express.Router();
const authMiddleware = require('../middlewares/auth');

// Debug middleware
router.use((req, res, next) => {
    console.log('User route accessed:', {
        method: req.method,
        path: req.path,
        fullUrl: req.originalUrl,
        userId: req.userId
    });
    next();
});

// Aplica o middleware de autenticação para todas as rotas
router.use(authMiddleware);

// Importa os roteadores específicos
const productsRouter = require('./user/products');
const ordersRouter = require('./user/orders');
const trainingsRouter = require('./user/trainings');

// Rotas específicas
router.use('/products', productsRouter);
router.use('/orders', ordersRouter);
router.use('/trainings', trainingsRouter);

module.exports = router;