const db = require('../src/config/database');

class AdminTrainingController {
    async list(req, res) {
        try {
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 10;
            const offset = (page - 1) * limit;

            // Busca total de registros
            const [total] = await db.execute(`
                SELECT COUNT(*) as count
                FROM trainings t
                WHERE t.deleted_at IS NULL
            `);

            // Busca registros paginados
            const [trainings] = await db.execute(`
                SELECT 
                    t.*,
                    (
                        SELECT COUNT(DISTINCT tm.id)
                        FROM training_modules tm
                        WHERE tm.training_id = t.id
                        AND tm.deleted_at IS NULL
                    ) as modules_count,
                    (
                        SELECT COUNT(DISTINCT l.id)
                        FROM lessons l
                        JOIN training_modules tm ON tm.id = l.module_id
                        WHERE tm.training_id = t.id
                        AND tm.deleted_at IS NULL
                        AND l.deleted_at IS NULL
                    ) as lessons_count
                FROM trainings t
                WHERE t.deleted_at IS NULL
                ORDER BY t.created_at DESC
                LIMIT ? OFFSET ?
            `, [limit, offset]);

            res.json({
                trainings,
                pagination: {
                    page,
                    limit,
                    totalItems: total[0].count,
                    totalPages: Math.ceil(total[0].count / limit)
                }
            });
        } catch (error) {
            console.error('Erro ao listar treinamentos:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async create(req, res) {
        try {
            const { name, description, category, price = 0 } = req.body;

            const [result] = await db.execute(
                'INSERT INTO trainings (name, description, category, price) VALUES (?, ?, ?, ?)', [name, description, category, price]
            );

            const [training] = await db.execute(
                'SELECT * FROM trainings WHERE id = ?', [result.insertId]
            );

            res.status(201).json(training[0]);
        } catch (error) {
            console.error('Erro ao criar treinamento:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async updateStatus(req, res) {
        try {
            const { id } = req.params;
            const { status } = req.body;

            if (!['draft', 'published'].includes(status)) {
                return res.status(400).json({ error: 'Status inválido' });
            }

            await db.execute(
                'UPDATE trainings SET status = ? WHERE id = ?', [status, id]
            );

            const [training] = await db.execute(
                'SELECT * FROM trainings WHERE id = ?', [id]
            );

            if (training.length === 0) {
                return res.status(404).json({ error: 'Treinamento não encontrado' });
            }

            res.json(training[0]);
        } catch (error) {
            console.error('Erro ao atualizar status do treinamento:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async delete(req, res) {
        try {
            const { id } = req.params;
            const now = new Date().toISOString().slice(0, 19).replace('T', ' ');

            await db.execute(
                'UPDATE trainings SET deleted_at = ? WHERE id = ?', [now, id]
            );

            res.json({ message: 'Treinamento excluído com sucesso' });
        } catch (error) {
            console.error('Erro ao excluir treinamento:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async getById(req, res) {
        try {
            const { id } = req.params;

            const [training] = await db.execute(
                'SELECT * FROM trainings WHERE id = ? AND deleted_at IS NULL', [id]
            );

            if (training.length === 0) {
                return res.status(404).json({ error: 'Treinamento não encontrado' });
            }

            res.json(training[0]);
        } catch (error) {
            console.error('Erro ao buscar treinamento:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }
}

module.exports = new AdminTrainingController();