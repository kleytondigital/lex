const express = require('express');
const router = express.Router();
const UserOrderController = require('../../controllers/UserOrderController');

// Debug middleware
router.use((req, res, next) => {
    console.log('Orders route accessed:', {
        method: req.method,
        path: req.path,
        fullUrl: req.originalUrl,
        params: req.params,
        userId: req.userId,
        body: req.body
    });
    next();
});

// Lista pedidos do usuário
router.get('/', UserOrderController.getMyOrders);

// Obtém detalhes de um pedido específico
router.get('/:id', UserOrderController.getOrderById);

// Cria um novo pedido
router.post('/', UserOrderController.createOrder);

// Processa o pagamento do pedido
router.post('/:id/pay', UserOrderController.processPayment);

module.exports = router;