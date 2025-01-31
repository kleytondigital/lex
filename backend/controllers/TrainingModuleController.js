const db = require('../src/database');
const { body, validationResult } = require('express-validator');
const ApiError = require('../utils/ApiError');

class TrainingModuleController {
    validate() {
        return [
            body('title').trim().isLength({ min: 3, max: 255 }).withMessage('Título deve ter entre 3 e 255 caracteres'),
            body('description').optional().trim(),
            body('order_index').optional().isInt({ min: 0 }).withMessage('Ordem deve ser um número inteiro positivo')
        ];
    }

    async getById(req, res, next) {
        try {
            const { id, training_id } = req.params;

            const query = `
                SELECT id, training_id, title, description, order_index, created_at, updated_at
                FROM training_modules
                WHERE id = ? AND training_id = ? AND deleted_at IS NULL
            `;

            const [modules] = await db.execute(query, [id, training_id]);

            if (modules.length === 0) {
                throw new ApiError(404, 'Módulo não encontrado');
            }

            res.json(modules[0]);
        } catch (error) {
            next(error);
        }
    }

    async list(req, res, next) {
        try {
            const { training_id } = req.params;

            const query = `
                SELECT id, training_id, title, description, order_index, created_at, updated_at
                FROM training_modules
                WHERE training_id = ? AND deleted_at IS NULL
                ORDER BY order_index ASC
            `;

            const [modules] = await db.execute(query, [training_id]);
            res.json(modules);
        } catch (error) {
            next(error);
        }
    }

    async create(req, res, next) {
        const connection = await db.getConnection();

        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                throw new ApiError(400, 'Dados inválidos', errors.array());
            }

            const { training_id } = req.params;
            const { title, description } = req.body;

            await connection.beginTransaction();

            // Pegar o maior order_index atual
            const [maxOrder] = await connection.execute(
                'SELECT COALESCE(MAX(order_index), -1) as max_order FROM training_modules WHERE training_id = ? AND deleted_at IS NULL', [training_id]
            );
            const order_index = maxOrder[0].max_order + 1;

            // Inserir o novo módulo
            const query = `
                INSERT INTO training_modules (training_id, title, description, order_index, created_at, updated_at)
                VALUES (?, ?, ?, ?, NOW(), NOW())
            `;

            const [result] = await connection.execute(query, [training_id, title, description, order_index]);

            await connection.commit();

            res.status(201).json({
                id: result.insertId,
                training_id: parseInt(training_id),
                title,
                description,
                order_index
            });
        } catch (error) {
            await connection.rollback();
            next(error);
        } finally {
            connection.release();
        }
    }

    async update(req, res, next) {
        const connection = await db.getConnection();

        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                throw new ApiError(400, 'Dados inválidos', errors.array());
            }

            const { id, training_id } = req.params;
            const { title, description, order_index } = req.body;

            await connection.beginTransaction();

            // Verificar se o módulo existe
            const [existingModule] = await connection.execute(
                'SELECT order_index FROM training_modules WHERE id = ? AND training_id = ? AND deleted_at IS NULL', [id, training_id]
            );

            if (existingModule.length === 0) {
                throw new ApiError(404, 'Módulo não encontrado');
            }

            // Se a ordem foi alterada, verificar e ajustar outros módulos
            if (order_index !== undefined && order_index !== existingModule[0].order_index) {
                await connection.execute(
                    `UPDATE training_modules 
                    SET order_index = order_index + (? < order_index ? -1 : 1)
                    WHERE training_id = ? 
                    AND deleted_at IS NULL
                    AND order_index BETWEEN ? AND ?`, [
                        existingModule[0].order_index,
                        training_id,
                        Math.min(existingModule[0].order_index, order_index),
                        Math.max(existingModule[0].order_index, order_index)
                    ]
                );
            }

            // Atualizar o módulo
            const query = `
                UPDATE training_modules
                SET title = ?, description = ?, order_index = ?, updated_at = NOW()
                WHERE id = ? AND training_id = ? AND deleted_at IS NULL
            `;

            await connection.execute(query, [title, description, order_index, id, training_id]);

            await connection.commit();

            res.json({
                id: parseInt(id),
                training_id: parseInt(training_id),
                title,
                description,
                order_index
            });
        } catch (error) {
            await connection.rollback();
            next(error);
        } finally {
            connection.release();
        }
    }

    async delete(req, res, next) {
        const connection = await db.getConnection();

        try {
            const { id, training_id } = req.params;

            await connection.beginTransaction();

            // Pegar a ordem do módulo a ser excluído
            const [module] = await connection.execute(
                'SELECT order_index FROM training_modules WHERE id = ? AND training_id = ? AND deleted_at IS NULL', [id, training_id]
            );

            if (module.length === 0) {
                throw new ApiError(404, 'Módulo não encontrado');
            }

            // Marcar como deletado
            await connection.execute(
                'UPDATE training_modules SET deleted_at = NOW() WHERE id = ?', [id]
            );

            // Atualizar a ordem dos módulos restantes
            await connection.execute(
                `UPDATE training_modules 
                SET order_index = order_index - 1
                WHERE training_id = ? 
                AND deleted_at IS NULL
                AND order_index > ?`, [training_id, module[0].order_index]
            );

            await connection.commit();

            res.status(204).send();
        } catch (error) {
            await connection.rollback();
            next(error);
        } finally {
            connection.release();
        }
    }

    async reorder(req, res, next) {
        const connection = await db.getConnection();

        try {
            const { training_id } = req.params;
            const { modules } = req.body;

            if (!Array.isArray(modules)) {
                throw new ApiError(400, 'Lista de módulos inválida');
            }

            await connection.beginTransaction();

            // Atualizar a ordem de cada módulo
            for (const [index, moduleId] of modules.entries()) {
                await connection.execute(
                    'UPDATE training_modules SET order_index = ? WHERE id = ? AND training_id = ? AND deleted_at IS NULL', [index, moduleId, training_id]
                );
            }

            await connection.commit();
            res.json({ message: 'Ordem dos módulos atualizada com sucesso' });
        } catch (error) {
            await connection.rollback();
            next(error);
        } finally {
            connection.release();
        }
    }
}

module.exports = new TrainingModuleController();