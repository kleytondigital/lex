const express = require('express');
const router = express.Router();
const UserProductController = require('../../controllers/UserProductController');

// Debug middleware
router.use((req, res, next) => {
    console.log('Products route accessed:', {
        method: req.method,
        path: req.path,
        fullUrl: req.originalUrl,
        params: req.params,
        userId: req.userId
    });
    next();
});

// Lista produtos do usuário (deve vir antes da rota com :id)
router.get('/my-products', UserProductController.getMyProducts);

// Lista produtos disponíveis (deve vir antes da rota com :id)
router.get('/available', UserProductController.getAvailable);

// Obtém detalhes de um produto específico
router.get('/:id', UserProductController.getById);

// Tratamento de erro 404 para rotas não encontradas em produtos
router.use((req, res) => {
    console.log('Rota não encontrada em products:', req.path);
    res.status(404).json({ message: 'Rota não encontrada' });
});

module.exports = router;