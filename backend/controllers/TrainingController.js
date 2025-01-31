const db = require('../src/database');
const { body, validationResult } = require('express-validator');
const ApiError = require('../utils/ApiError');

class TrainingController {
    validate() {
        return [
            body('name').trim().isLength({ min: 3, max: 255 }).withMessage('Nome deve ter entre 3 e 255 caracteres'),
            body('description').optional().trim(),
            body('category').trim().notEmpty().withMessage('Categoria é obrigatória'),
            body('price').isFloat({ min: 0 }).withMessage('Preço deve ser um número positivo'),
            body('status').isIn(['draft', 'published']).withMessage('Status inválido')
        ];
    }

    async create(req, res, next) {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                throw new ApiError(400, 'Dados inválidos', errors.array());
            }

            const { name, description, category, price, status = 'draft' } = req.body;
            const userId = req.userId;

            const query = `
                INSERT INTO trainings (name, description, category, price, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, NOW(), NOW())
            `;

            const [result] = await db.execute(query, [name, description, category, price, status]);

            res.status(201).json({
                id: result.insertId,
                name,
                description,
                category,
                price,
                status
            });
        } catch (error) {
            next(error);
        }
    }

    async list(req, res, next) {
        try {
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 10;
            const offset = (page - 1) * limit;
            const search = req.query.search || '';

            const countQuery = `
                SELECT COUNT(*) as total
                FROM trainings
                WHERE deleted_at IS NULL
                ${search ? 'AND name LIKE ?' : ''}
            `;

            const [countResult] = await db.execute(
                countQuery,
                search ? [`%${search}%`] : []
            );

            const totalItems = countResult[0].total;
            const totalPages = Math.ceil(totalItems / limit);

            const query = `
                SELECT id, name, description, category, price, status, thumbnail, created_at, updated_at
                FROM trainings
                WHERE deleted_at IS NULL
                ${search ? 'AND name LIKE ?' : ''}
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            `;

            const [trainings] = await db.execute(
                query,
                search ? [`%${search}%`, limit, offset] : [limit, offset]
            );

            res.json({
                data: trainings,
                pagination: {
                    page,
                    limit,
                    totalItems,
                    totalPages
                }
            });
        } catch (error) {
            next(error);
        }
    }

    async getById(req, res) {
        try {
            const { id } = req.params;
            const query = `
                SELECT id, name, description, category, price, status, thumbnail, created_at, updated_at
                FROM trainings
                WHERE id = ? AND deleted_at IS NULL
            `;

            const [trainings] = await db.execute(query, [id]);

            if (trainings.length === 0) {
                return res.status(404).json({ error: 'Treinamento não encontrado' });
            }

            res.json(trainings[0]);
        } catch (error) {
            console.error('Erro ao buscar treinamento:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async update(req, res) {
        try {
            const { id } = req.params;
            const { name, description, category, price, status } = req.body;

            const query = `
                UPDATE trainings
                SET name = ?, description = ?, category = ?, price = ?, status = ?, updated_at = NOW()
                WHERE id = ? AND deleted_at IS NULL
            `;

            const [result] = await db.execute(query, [name, description, category, price, status, id]);

            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'Treinamento não encontrado' });
            }

            res.json({ id, name, description, category, price, status });
        } catch (error) {
            console.error('Erro ao atualizar treinamento:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async updateStatus(req, res) {
        try {
            const { id } = req.params;
            const { status } = req.body;

            let query;
            if (status === 'deleted') {
                query = `
                    UPDATE trainings
                    SET deleted_at = NOW(), status = 'deleted'
                    WHERE id = ? AND deleted_at IS NULL
                `;
            } else {
                query = `
                    UPDATE trainings
                    SET status = ?, updated_at = NOW()
                    WHERE id = ? AND deleted_at IS NULL
                `;
            }

            const [result] = await db.execute(query, status === 'deleted' ? [id] : [status, id]);

            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'Treinamento não encontrado' });
            }

            res.json({ id, status });
        } catch (error) {
            console.error('Erro ao atualizar status do treinamento:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }
}

module.exports = new TrainingController();