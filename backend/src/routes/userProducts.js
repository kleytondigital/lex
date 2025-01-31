const express = require('express');
const router = express.Router();
const UserProductController = require('../controllers/UserProductController');
const authMiddleware = require('../middlewares/auth');

// Aplica o middleware de autenticação para todas as rotas
router.use(authMiddleware);

// Lista produtos disponíveis
router.get('/available', UserProductController.getAvailable);

// Obtém detalhes de um produto específico
router.get('/:id', UserProductController.getById);

module.exports = router;