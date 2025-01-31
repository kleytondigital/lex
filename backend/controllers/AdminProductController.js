const db = require('../src/config/database');

class AdminProductController {
    // Listar produtos
    async list(req, res) {
        try {
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 10;
            const offset = (page - 1) * limit;

            // Busca total de registros
            const [total] = await db.execute(`
                SELECT COUNT(*) as count
                FROM products
                WHERE deleted_at IS NULL
            `);

            // Busca registros paginados
            const [products] = await db.execute(`
                SELECT 
                    p.*,
                    (
                        SELECT COUNT(*)
                        FROM orders o
                        WHERE o.product_id = p.id
                        AND o.status = 'paid'
                    ) as total_sales,
                    (
                        SELECT SUM(amount)
                        FROM orders o
                        WHERE o.product_id = p.id
                        AND o.status = 'paid'
                    ) as total_revenue
                FROM products p
                WHERE p.deleted_at IS NULL
                ORDER BY p.created_at DESC
                LIMIT ? OFFSET ?
            `, [limit, offset]);

            res.json({
                products,
                pagination: {
                    page,
                    limit,
                    totalItems: total[0].count,
                    totalPages: Math.ceil(total[0].count / limit)
                }
            });
        } catch (error) {
            console.error('Erro ao listar produtos:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    // Criar produto
    async create(req, res) {
        try {
            const {
                name,
                description,
                price,
                type = 'landpage',
                features = [],
                thumbnail = null,
                status = 'active'
            } = req.body;

            const [result] = await db.execute(`
                INSERT INTO products (
                    name,
                    description,
                    price,
                    type,
                    features,
                    thumbnail,
                    status,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
            `, [
                name,
                description,
                price,
                type,
                JSON.stringify(features),
                thumbnail,
                status
            ]);

            const [product] = await db.execute(
                'SELECT * FROM products WHERE id = ?', [result.insertId]
            );

            res.status(201).json(product[0]);
        } catch (error) {
            console.error('Erro ao criar produto:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    // Buscar produto por ID
    async getById(req, res) {
        try {
            const [products] = await db.execute(`
                SELECT 
                    p.*,
                    (
                        SELECT COUNT(*)
                        FROM orders o
                        WHERE o.product_id = p.id
                        AND o.status = 'paid'
                    ) as total_sales,
                    (
                        SELECT SUM(amount)
                        FROM orders o
                        WHERE o.product_id = p.id
                        AND o.status = 'paid'
                    ) as total_revenue
                FROM products p
                WHERE p.id = ?
                AND p.deleted_at IS NULL
            `, [req.params.id]);

            if (products.length === 0) {
                return res.status(404).json({ error: 'Produto não encontrado' });
            }

            res.json(products[0]);
        } catch (error) {
            console.error('Erro ao buscar produto:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    // Atualizar produto
    async update(req, res) {
        try {
            const { id } = req.params;
            const {
                name,
                description,
                price,
                type,
                features,
                thumbnail,
                status
            } = req.body;

            await db.execute(`
                UPDATE products
                SET 
                    name = ?,
                    description = ?,
                    price = ?,
                    type = ?,
                    features = ?,
                    thumbnail = ?,
                    status = ?
                WHERE id = ?
            `, [
                name,
                description,
                price,
                type,
                JSON.stringify(features),
                thumbnail,
                status,
                id
            ]);

            const [product] = await db.execute(
                'SELECT * FROM products WHERE id = ?', [id]
            );

            if (product.length === 0) {
                return res.status(404).json({ error: 'Produto não encontrado' });
            }

            res.json(product[0]);
        } catch (error) {
            console.error('Erro ao atualizar produto:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    // Deletar produto (soft delete)
    async delete(req, res) {
        try {
            const { id } = req.params;
            const now = new Date().toISOString().slice(0, 19).replace('T', ' ');

            await db.execute(
                'UPDATE products SET deleted_at = ? WHERE id = ?', [now, id]
            );

            res.json({ message: 'Produto deletado com sucesso' });
        } catch (error) {
            console.error('Erro ao deletar produto:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    // Atualizar status do produto
    async updateStatus(req, res) {
        try {
            const { id } = req.params;
            const { status } = req.body;

            if (!['active', 'inactive'].includes(status)) {
                return res.status(400).json({ error: 'Status inválido' });
            }

            await db.execute(
                'UPDATE products SET status = ? WHERE id = ?', [status, id]
            );

            const [product] = await db.execute(
                'SELECT * FROM products WHERE id = ?', [id]
            );

            if (product.length === 0) {
                return res.status(404).json({ error: 'Produto não encontrado' });
            }

            res.json(product[0]);
        } catch (error) {
            console.error('Erro ao atualizar status:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }
}

module.exports = new AdminProductController();