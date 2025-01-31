const express = require('express');
const router = express.Router();
const AdminProductController = require('../../controllers/AdminProductController');

// Listar produtos
router.get('/', AdminProductController.list);

// Criar produto
router.post('/', AdminProductController.create);

// Buscar produto por ID
router.get('/:id', AdminProductController.getById);

// Atualizar produto
router.put('/:id', AdminProductController.update);

// Deletar produto
router.delete('/:id', AdminProductController.delete);

// Atualizar status do produto
router.patch('/:id/status', AdminProductController.updateStatus);

module.exports = router;