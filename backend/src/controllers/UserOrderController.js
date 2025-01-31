const connection = require('../config/database');

class UserOrderController {
    // Lista todos os pedidos do usuário
    static async getMyOrders(req, res) {
        console.log('UserOrderController.getMyOrders called');
        try {
            const query = `
                SELECT 
                    o.*,
                    p.name as product_name,
                    p.type as product_type
                FROM orders o
                JOIN products p ON o.product_id = p.id
                WHERE o.user_id = ?
                    AND o.status = 'paid'
                ORDER BY o.created_at DESC
            `;

            console.log('Executing query with user_id:', req.userId);
            const [rows] = await connection.execute(query, [req.userId]);
            console.log('Query result:', rows);

            res.json({ orders: rows });
        } catch (error) {
            console.error('Erro ao buscar pedidos:', error);
            res.status(500).json({ message: 'Erro ao buscar pedidos' });
        }
    }

    // Obtém detalhes de um pedido específico
    static async getOrderById(req, res) {
        console.log('UserOrderController.getOrderById called');
        try {
            const query = `
                SELECT 
                    o.*,
                    p.name as product_name,
                    p.type as product_type
                FROM orders o
                JOIN products p ON o.product_id = p.id
                WHERE o.id = ?
                    AND o.user_id = ?
            `;

            const [rows] = await connection.execute(query, [req.params.id, req.userId]);

            if (rows.length === 0) {
                return res.status(404).json({ message: 'Pedido não encontrado' });
            }

            res.json(rows[0]);
        } catch (error) {
            console.error('Erro ao buscar pedido:', error);
            res.status(500).json({ message: 'Erro ao buscar pedido' });
        }
    }

    // Cria um novo pedido
    static async createOrder(req, res) {
        console.log('UserOrderController.createOrder called');
        try {
            const { productId } = req.body;

            // Validar se o produto existe e pegar o preço
            const [products] = await connection.execute(
                'SELECT price FROM products WHERE id = ? AND status = "active"', [productId]
            );

            if (products.length === 0) {
                return res.status(404).json({ message: 'Produto não encontrado' });
            }

            const product = products[0];

            // Criar o pedido
            const [result] = await connection.execute(
                `INSERT INTO orders (user_id, product_id, amount, status) 
                 VALUES (?, ?, ?, 'pending')`, [req.userId, productId, product.price]
            );

            console.log('Pedido criado:', result.insertId);

            // Retornar o ID do pedido criado
            res.status(201).json({
                orderId: result.insertId,
                message: 'Pedido criado com sucesso'
            });
        } catch (error) {
            console.error('Erro ao criar pedido:', error);
            res.status(500).json({ message: 'Erro ao criar pedido' });
        }
    }

    // Processa o pagamento do pedido
    static async processPayment(req, res) {
        console.log('UserOrderController.processPayment called');
        try {
            // Verificar se o pedido existe e pertence ao usuário
            const [orders] = await connection.execute(
                'SELECT * FROM orders WHERE id = ? AND user_id = ?', [req.params.id, req.userId]
            );

            if (orders.length === 0) {
                return res.status(404).json({ message: 'Pedido não encontrado' });
            }

            // Atualizar status do pedido
            await connection.execute(
                'UPDATE orders SET status = "paid" WHERE id = ?', [req.params.id]
            );

            // Criar acesso ao produto
            await connection.execute(
                'INSERT INTO user_products (user_id, product_id, order_id) VALUES (?, ?, ?)', [req.userId, orders[0].product_id, req.params.id]
            );

            res.json({ message: 'Pagamento processado com sucesso' });
        } catch (error) {
            console.error('Erro ao processar pagamento:', error);
            res.status(500).json({ message: 'Erro ao processar pagamento' });
        }
    }
}

module.exports = UserOrderController;