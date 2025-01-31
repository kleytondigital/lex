const express = require('express');
const router = express.Router();
const UserProductController = require('../../controllers/UserProductController');

// Verificar acesso a um produto
router.get('/:productId/access', UserProductController.checkAccess);

// Listar produtos do usuário
router.get('/my-products', UserProductController.listUserProducts);

// Listar produtos disponíveis para compra
router.get('/available', UserProductController.listAvailableProducts);

module.exports = router;