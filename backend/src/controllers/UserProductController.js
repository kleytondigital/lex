const connection = require('../config/database');

class UserProductController {
    // Lista produtos disponíveis para compra
    static async getAvailable(req, res) {
        console.log('UserProductController.getAvailable called');
        try {
            const query = `
                SELECT 
                    p.*,
                    IF(up.id IS NOT NULL, true, false) as has_access
                FROM products p
                LEFT JOIN user_products up ON p.id = up.product_id 
                    AND up.user_id = ?
                    AND (up.expires_at IS NULL OR up.expires_at > NOW())
                WHERE p.status = 'active'
                    AND p.deleted_at IS NULL
                ORDER BY p.created_at DESC
            `;

            console.log('Executing query with user_id:', req.userId);
            const [rows] = await connection.execute(query, [req.userId]);

            // Parse features JSON para cada produto
            const products = rows.map(product => ({
                ...product,
                features: product.features ? JSON.parse(product.features) : []
            }));

            console.log('Query result:', products);
            res.json({ products });
        } catch (error) {
            console.error('Erro ao buscar produtos:', error);
            res.status(500).json({ message: 'Erro ao buscar produtos' });
        }
    }

    // Obtém detalhes de um produto específico
    static async getById(req, res) {
        console.log('UserProductController.getById called with id:', req.params.id);

        try {
            // Validar se o ID é um número válido
            const productId = parseInt(req.params.id);
            if (isNaN(productId)) {
                console.log('ID inválido fornecido:', req.params.id);
                return res.status(400).json({ message: 'ID do produto inválido' });
            }

            const query = `
                SELECT 
                    p.*,
                    IF(up.id IS NOT NULL, true, false) as has_access
                FROM products p
                LEFT JOIN user_products up ON p.id = up.product_id 
                    AND up.user_id = ?
                    AND (up.expires_at IS NULL OR up.expires_at > NOW())
                WHERE p.id = ? 
                    AND p.status = 'active'
                    AND p.deleted_at IS NULL
            `;

            console.log('Executing query with user_id:', req.userId, 'and product_id:', productId);
            const [rows] = await connection.execute(query, [req.userId, productId]);
            console.log('Query returned rows:', rows.length);

            if (rows.length === 0) {
                console.log('Produto não encontrado com ID:', productId);
                return res.status(404).json({ message: 'Produto não encontrado' });
            }

            // Parse features JSON
            const product = {
                ...rows[0],
                features: rows[0].features ? JSON.parse(rows[0].features) : []
            };

            console.log('Produto encontrado:', product.id, product.name);
            res.json(product);
        } catch (error) {
            console.error('Erro ao buscar produto:', error);
            res.status(500).json({ message: 'Erro ao buscar produto' });
        }
    }

    // Lista produtos do usuário
    static async getMyProducts(req, res) {
        console.log('UserProductController.getMyProducts called');
        try {
            const query = `
                SELECT 
                    p.*,
                    up.expires_at,
                    up.created_at as access_created_at
                FROM user_products up
                JOIN products p ON p.id = up.product_id
                WHERE up.user_id = ?
                    AND (up.expires_at IS NULL OR up.expires_at > NOW())
                    AND p.deleted_at IS NULL
                ORDER BY up.created_at DESC
            `;

            console.log('Executing query with user_id:', req.userId);
            const [rows] = await connection.execute(query, [req.userId]);

            // Parse features JSON para cada produto
            const products = rows.map(product => ({
                ...product,
                features: product.features ? JSON.parse(product.features) : []
            }));

            console.log('Query result:', products);
            res.json({ products });
        } catch (error) {
            console.error('Erro ao buscar produtos do usuário:', error);
            res.status(500).json({ message: 'Erro ao buscar produtos do usuário' });
        }
    }
}

module.exports = UserProductController;