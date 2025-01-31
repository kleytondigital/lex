const express = require('express');
const router = express.Router();
const orderController = require('../controllers/orderController');
const authMiddleware = require('../middlewares/auth');

// Rotas que requerem autenticação
router.use(authMiddleware);
router.get('/user/orders', orderController.getUserOrders);
router.post('/:id/payment', orderController.processPayment);

// Webhook do Mercado Pago (rota pública)
router.post('/webhook/mercadopago', orderController.webhookMP);

module.exports = router;