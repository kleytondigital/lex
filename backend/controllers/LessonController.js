const db = require('../src/database');
const { body, validationResult } = require('express-validator');
const ApiError = require('../utils/ApiError');

class LessonController {
    validate() {
        return [
            body('title').trim().isLength({ min: 3, max: 255 }).withMessage('Título deve ter entre 3 e 255 caracteres'),
            body('description').optional().trim(),
            body('content_type').isIn(['video', 'document']).withMessage('Tipo de conteúdo inválido'),
            body('video_url').optional().trim().isURL().withMessage('URL do vídeo inválida'),
            body('duration').optional().trim(),
            body('order_index').optional().isInt({ min: 0 }).withMessage('Ordem deve ser um número inteiro positivo')
        ];
    }

    async getById(req, res, next) {
        try {
            const { id, module_id } = req.params;

            const query = `
                SELECT id, module_id, title, description, content_type, video_url, duration, order_index, created_at, updated_at
                FROM lessons
                WHERE id = ? AND module_id = ? AND deleted_at IS NULL
            `;

            const [lessons] = await db.execute(query, [id, module_id]);

            if (lessons.length === 0) {
                throw new ApiError(404, 'Aula não encontrada');
            }

            res.json(lessons[0]);
        } catch (error) {
            next(error);
        }
    }

    async list(req, res, next) {
        try {
            const { training_id, module_id } = req.params;

            const query = `
                SELECT id, module_id, title, description, content_type, video_url, duration, order_index, created_at, updated_at
                FROM lessons
                WHERE module_id = ? AND deleted_at IS NULL
                ORDER BY order_index ASC
            `;

            const [lessons] = await db.execute(query, [module_id]);
            res.json(lessons);
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

            const { module_id } = req.params;
            const { title, description, content_type, video_url, duration } = req.body;

            await connection.beginTransaction();

            // Get the highest order_index
            const [maxOrder] = await connection.execute(
                'SELECT COALESCE(MAX(order_index), -1) as max_order FROM lessons WHERE module_id = ? AND deleted_at IS NULL', [module_id]
            );
            const order_index = maxOrder[0].max_order + 1;

            // Insert the new lesson
            const query = `
                INSERT INTO lessons (module_id, title, description, content_type, video_url, duration, order_index, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
            `;

            const [result] = await connection.execute(query, [
                module_id,
                title,
                description,
                content_type,
                video_url,
                duration,
                order_index
            ]);

            await connection.commit();

            res.status(201).json({
                id: result.insertId,
                module_id: parseInt(module_id),
                title,
                description,
                content_type,
                video_url,
                duration,
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

            const { id, module_id } = req.params;
            const { title, description, content_type, video_url, duration, order_index } = req.body;

            await connection.beginTransaction();

            // Check if lesson exists
            const [existingLesson] = await connection.execute(
                'SELECT order_index FROM lessons WHERE id = ? AND module_id = ? AND deleted_at IS NULL', [id, module_id]
            );

            if (existingLesson.length === 0) {
                throw new ApiError(404, 'Aula não encontrada');
            }

            // If order changed, adjust other lessons
            if (order_index !== undefined && order_index !== existingLesson[0].order_index) {
                await connection.execute(
                    `UPDATE lessons 
                    SET order_index = order_index + (? < order_index ? -1 : 1)
                    WHERE module_id = ? 
                    AND deleted_at IS NULL
                    AND order_index BETWEEN ? AND ?`, [
                        existingLesson[0].order_index,
                        module_id,
                        Math.min(existingLesson[0].order_index, order_index),
                        Math.max(existingLesson[0].order_index, order_index)
                    ]
                );
            }

            // Update the lesson
            const query = `
                UPDATE lessons
                SET title = ?, description = ?, content_type = ?, video_url = ?, duration = ?, order_index = ?, updated_at = NOW()
                WHERE id = ? AND module_id = ? AND deleted_at IS NULL
            `;

            await connection.execute(query, [
                title,
                description,
                content_type,
                video_url,
                duration,
                order_index,
                id,
                module_id
            ]);

            await connection.commit();

            res.json({
                id: parseInt(id),
                module_id: parseInt(module_id),
                title,
                description,
                content_type,
                video_url,
                duration,
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
            const { id, module_id } = req.params;

            await connection.beginTransaction();

            // Get the lesson's order
            const [lesson] = await connection.execute(
                'SELECT order_index FROM lessons WHERE id = ? AND module_id = ? AND deleted_at IS NULL', [id, module_id]
            );

            if (lesson.length === 0) {
                throw new ApiError(404, 'Aula não encontrada');
            }

            // Mark as deleted
            await connection.execute(
                'UPDATE lessons SET deleted_at = NOW() WHERE id = ?', [id]
            );

            // Update remaining lessons order
            await connection.execute(
                `UPDATE lessons 
                SET order_index = order_index - 1
                WHERE module_id = ? 
                AND deleted_at IS NULL
                AND order_index > ?`, [module_id, lesson[0].order_index]
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
            const { module_id } = req.params;
            const { lessons } = req.body;

            if (!Array.isArray(lessons)) {
                throw new ApiError(400, 'Lista de aulas inválida');
            }

            await connection.beginTransaction();

            // Update each lesson's order
            for (const [index, lessonId] of lessons.entries()) {
                await connection.execute(
                    'UPDATE lessons SET order_index = ? WHERE id = ? AND module_id = ? AND deleted_at IS NULL', [index, lessonId, module_id]
                );
            }

            await connection.commit();
            res.json({ message: 'Ordem das aulas atualizada com sucesso' });
        } catch (error) {
            await connection.rollback();
            next(error);
        } finally {
            connection.release();
        }
    }
}

module.exports = new LessonController();