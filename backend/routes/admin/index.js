const express = require('express');
const router = express.Router();
const authMiddleware = require('../../src/middlewares/auth');
const adminMiddleware = require('../../src/middlewares/admin');
const AdminTrainingController = require('../../controllers/AdminTrainingController');
const AdminDashboardController = require('../../controllers/AdminDashboardController');
const productsRoutes = require('./products');

// Middleware para verificar se o usuário está autenticado e é admin
router.use(authMiddleware);
router.use(adminMiddleware);

// Rotas de usuários
router.use('/users', require('./users'));

// Rotas de treinamentos
router.use('/trainings', require('./trainings'));

// Rotas de landing pages
router.use('/landpages', require('./landpages'));

// Rotas de treinamentos
router.get('/trainings', AdminTrainingController.list);
router.post('/trainings', AdminTrainingController.create);
router.get('/trainings/:id', AdminTrainingController.getById);
router.delete('/trainings/:id', AdminTrainingController.delete);
router.patch('/trainings/:id/status', AdminTrainingController.updateStatus);

// Rotas do dashboard
router.get('/dashboard/stats', AdminDashboardController.getStats);

// Registrar rotas de produtos
router.use('/products', productsRoutes);

module.exports = router;