const Landpage = require('../../models/Landpage');
const paymentService = require('../services/paymentService');

class OrderController {
    // Processar pagamento
    async processPayment(req, res) {
        try {
            const orderId = req.params.id;
            const order = await Landpage.getOrderById(orderId);

            if (!order) {
                return res.status(404).json({ error: 'Pedido não encontrado' });
            }

            if (order.user_id !== req.user.id) {
                return res.status(403).json({ error: 'Acesso negado' });
            }

            const preference = await paymentService.createPayment(order, req.user);
            res.json(preference);
        } catch (error) {
            console.error('Erro ao processar pagamento:', error);
            res.status(500).json({ error: 'Erro ao processar pagamento' });
        }
    }

    // Webhook do Mercado Pago
    async webhookMP(req, res) {
        try {
            await paymentService.handleWebhook(req.body);
            res.sendStatus(200);
        } catch (error) {
            console.error('Erro no webhook:', error);
            res.sendStatus(500);
        }
    }

    // Listar pedidos do usuário
    async getUserOrders(req, res) {
        try {
            const orders = await Landpage.getUserOrders(req.user.id);
            res.json(orders);
        } catch (error) {
            res.status(500).json({ error: 'Erro ao buscar pedidos' });
        }
    }
}

module.exports = new OrderController();