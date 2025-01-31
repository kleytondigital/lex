const db = require('../src/config/database');

class UserProductController {
    // Verificar acesso a um produto
    async checkAccess(req, res) {
        try {
            const { productId } = req.params;
            const userId = req.user.id;

            const [access] = await db.execute(`
                SELECT 
                    up.*,
                    p.name as product_name,
                    p.type as product_type
                FROM user_products up
                JOIN products p ON p.id = up.product_id
                WHERE up.user_id = ?
                AND up.product_id = ?
                AND (up.expires_at IS NULL OR up.expires_at > NOW())
            `, [userId, productId]);

            res.json({
                hasAccess: access.length > 0,
                product: access[0] || null
            });
        } catch (error) {
            console.error('Erro ao verificar acesso:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    // Listar produtos do usuário
    async listUserProducts(req, res) {
        try {
            const userId = req.user.id;

            const [products] = await db.execute(`
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
            `, [userId]);

            res.json({ products });
        } catch (error) {
            console.error('Erro ao listar produtos do usuário:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    // Listar produtos disponíveis para compra
    async listAvailableProducts(req, res) {
        try {
            const userId = req.user.id;

            const [products] = await db.execute(`
                SELECT 
                    p.*,
                    CASE 
                        WHEN up.id IS NOT NULL THEN true
                        ELSE false
                    END as has_access
                FROM products p
                LEFT JOIN user_products up ON 
                    up.product_id = p.id 
                    AND up.user_id = ?
                    AND (up.expires_at IS NULL OR up.expires_at > NOW())
                WHERE p.status = 'active'
                AND p.deleted_at IS NULL
                ORDER BY p.created_at DESC
            `, [userId]);

            res.json({ products });
        } catch (error) {
            console.error('Erro ao listar produtos disponíveis:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    // Conceder acesso a um produto
    async grantAccess(req, res) {
        try {
            const { userId, productId, orderId, expiresAt = null } = req.body;

            // Verificar se já existe acesso
            const [existingAccess] = await db.execute(`
                SELECT id 
                FROM user_products 
                WHERE user_id = ? 
                AND product_id = ?
                AND (expires_at IS NULL OR expires_at > NOW())
            `, [userId, productId]);

            if (existingAccess.length > 0) {
                return res.status(400).json({ error: 'Usuário já tem acesso a este produto' });
            }

            // Conceder acesso
            await db.execute(`
                INSERT INTO user_products (
                    user_id,
                    product_id,
                    order_id,
                    expires_at
                ) VALUES (?, ?, ?, ?)
            `, [userId, productId, orderId, expiresAt]);

            res.json({ message: 'Acesso concedido com sucesso' });
        } catch (error) {
            console.error('Erro ao conceder acesso:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    // Revogar acesso a um produto
    async revokeAccess(req, res) {
        try {
            const { userId, productId } = req.params;

            await db.execute(`
                UPDATE user_products
                SET expires_at = NOW()
                WHERE user_id = ?
                AND product_id = ?
                AND (expires_at IS NULL OR expires_at > NOW())
            `, [userId, productId]);

            res.json({ message: 'Acesso revogado com sucesso' });
        } catch (error) {
            console.error('Erro ao revogar acesso:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }
}

module.exports = new UserProductController();