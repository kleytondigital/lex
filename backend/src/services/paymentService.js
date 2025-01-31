const mercadopago = require('mercadopago');
const config = require('../config/config');

// Configurar credenciais do Mercado Pago
mercadopago.configure({
    access_token: config.mercadoPago.accessToken
});

class PaymentService {
    async createPayment(order, user) {
        try {
            const preference = {
                items: [{
                    title: 'Landing Pages Alexandria',
                    unit_price: order.amount,
                    quantity: 1,
                    currency_id: 'BRL'
                }],
                payer: {
                    email: user.email,
                    name: user.name
                },
                external_reference: order.id.toString(),
                back_urls: {
                    success: `${config.frontendUrl}/dashboard/landpage/config/${order.id}`,
                    pending: `${config.frontendUrl}/dashboard/orders`,
                    failure: `${config.frontendUrl}/dashboard/orders`
                },
                auto_return: 'approved',
                notification_url: `${config.apiUrl}/webhook/mercadopago`
            };

            const response = await mercadopago.preferences.create(preference);
            return response.body;
        } catch (error) {
            console.error('Erro ao criar pagamento:', error);
            throw new Error('Erro ao processar pagamento');
        }
    }

    async handleWebhook(data) {
        try {
            if (data.type === 'payment') {
                const payment = await mercadopago.payment.findById(data.data.id);
                const orderId = payment.body.external_reference;
                const status = payment.body.status;

                // Atualizar status do pedido
                await this.updateOrderStatus(orderId, status);
            }
        } catch (error) {
            console.error('Erro ao processar webhook:', error);
            throw error;
        }
    }

    async updateOrderStatus(orderId, paymentStatus) {
        const conn = await pool.getConnection();

        try {
            await conn.beginTransaction();

            let orderStatus;
            switch (paymentStatus) {
                case 'approved':
                    orderStatus = 'paid';
                    break;
                case 'pending':
                    orderStatus = 'pending';
                    break;
                case 'rejected':
                    orderStatus = 'cancelled';
                    break;
                default:
                    orderStatus = 'pending';
            }

            await conn.query(
                'UPDATE orders SET status = ?, payment_id = ? WHERE id = ?', [orderStatus, paymentStatus, orderId]
            );

            await conn.commit();
        } catch (error) {
            await conn.rollback();
            throw error;
        } finally {
            conn.release();
        }
    }
}

module.exports = new PaymentService();