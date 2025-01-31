const express = require('express');
const router = express.Router();
const authMiddleware = require('../src/middlewares/auth');
const authRoutes = require('../src/routes/auth');
const adminRoutes = require('./adminRoutes');
const userTrainingsRoutes = require('./userTrainingsRoutes');

// Rotas públicas
router.use('/auth', authRoutes);

// Middleware de autenticação
router.use(authMiddleware);

// Rotas protegidas
router.use('/admin', adminRoutes);
router.use('/user/trainings', userTrainingsRoutes);

module.exports = router;