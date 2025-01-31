const connection = require('../config/database');

class UserTrainingsController {
    // Lista treinamentos em progresso do usuário
    static async getInProgress(req, res) {
        try {
            const query = `
                SELECT 
                    t.*,
                    ut.progress,
                    (
                        SELECT COUNT(*) 
                        FROM training_modules 
                        WHERE training_id = t.id
                    ) as total_modules
                FROM trainings t
                JOIN user_trainings ut ON t.id = ut.training_id
                WHERE ut.user_id = ?
                    AND t.status = 'published'
                ORDER BY ut.last_accessed_at DESC
            `;

            const [rows] = await connection.execute(query, [req.userId]);
            res.json(rows);
        } catch (error) {
            console.error('Erro ao buscar treinamentos em progresso:', error);
            res.status(500).json({ message: 'Erro ao buscar treinamentos em progresso' });
        }
    }

    // Lista treinamentos bloqueados (não matriculados)
    static async getLocked(req, res) {
        try {
            const query = `
                SELECT 
                    t.*,
                    (
                        SELECT COUNT(*) 
                        FROM training_modules 
                        WHERE training_id = t.id
                    ) as total_modules
                FROM trainings t
                WHERE t.id NOT IN (
                    SELECT training_id 
                    FROM user_trainings 
                    WHERE user_id = ?
                )
                AND t.status = 'published'
                ORDER BY t.created_at DESC
            `;

            const [rows] = await connection.execute(query, [req.userId]);
            res.json(rows);
        } catch (error) {
            console.error('Erro ao buscar treinamentos bloqueados:', error);
            res.status(500).json({ message: 'Erro ao buscar treinamentos bloqueados' });
        }
    }

    // Lista treinamentos disponíveis (publicados)
    static async getAvailable(req, res) {
        try {
            const query = `
                SELECT 
                    t.*,
                    (
                        SELECT COUNT(*) 
                        FROM training_modules 
                        WHERE training_id = t.id
                    ) as total_modules
                FROM trainings t
                WHERE t.status = 'published'
                ORDER BY t.created_at DESC
            `;

            const [rows] = await connection.execute(query);
            res.json(rows);
        } catch (error) {
            console.error('Erro ao buscar treinamentos disponíveis:', error);
            res.status(500).json({ message: 'Erro ao buscar treinamentos disponíveis' });
        }
    }

    // Busca detalhes de um treinamento específico
    static async getById(req, res) {
        try {
            const query = `
                SELECT 
                    t.*,
                    COALESCE(ut.progress, 0) as progress,
                    (
                        SELECT COUNT(*) 
                        FROM training_modules 
                        WHERE training_id = t.id
                    ) as total_modules
                FROM trainings t
                LEFT JOIN user_trainings ut ON t.id = ut.training_id AND ut.user_id = ?
                WHERE t.id = ?
                    AND t.status = 'published'
            `;

            const [rows] = await connection.execute(query, [req.userId, req.params.id]);

            if (rows.length === 0) {
                return res.status(404).json({ message: 'Treinamento não encontrado' });
            }

            res.json(rows[0]);
        } catch (error) {
            console.error('Erro ao buscar treinamento:', error);
            res.status(500).json({ message: 'Erro ao buscar treinamento' });
        }
    }

    // Busca módulos de um treinamento
    static async getModules(req, res) {
        try {
            const query = `
                SELECT 
                    m.*,
                    (
                        SELECT COUNT(*) 
                        FROM lessons 
                        WHERE module_id = m.id
                    ) as total_lessons
                FROM training_modules m
                WHERE m.training_id = ?
                ORDER BY m.order_index
            `;

            const [rows] = await connection.execute(query, [req.params.id]);
            res.json(rows);
        } catch (error) {
            console.error('Erro ao buscar módulos:', error);
            res.status(500).json({ message: 'Erro ao buscar módulos' });
        }
    }

    // Busca detalhes de um módulo específico
    static async getModuleDetails(req, res) {
        try {
            const query = `
                SELECT 
                    m.*,
                    (
                        SELECT COUNT(*) 
                        FROM lessons 
                        WHERE module_id = m.id
                    ) as total_lessons
                FROM training_modules m
                WHERE m.id = ?
                    AND m.training_id = ?
            `;

            const [rows] = await connection.execute(query, [req.params.moduleId, req.params.id]);

            if (rows.length === 0) {
                return res.status(404).json({ message: 'Módulo não encontrado' });
            }

            res.json(rows[0]);
        } catch (error) {
            console.error('Erro ao buscar módulo:', error);
            res.status(500).json({ message: 'Erro ao buscar módulo' });
        }
    }

    // Busca detalhes de uma aula específica
    static async getLessonDetails(req, res) {
        try {
            const query = `
                SELECT l.*
                FROM lessons l
                JOIN training_modules m ON l.module_id = m.id
                WHERE l.id = ?
                    AND m.id = ?
                    AND m.training_id = ?
            `;

            const [rows] = await connection.execute(query, [
                req.params.lessonId,
                req.params.moduleId,
                req.params.id
            ]);

            if (rows.length === 0) {
                return res.status(404).json({ message: 'Aula não encontrada' });
            }

            res.json(rows[0]);
        } catch (error) {
            console.error('Erro ao buscar aula:', error);
            res.status(500).json({ message: 'Erro ao buscar aula' });
        }
    }

    // Atualiza o progresso do usuário em um treinamento
    static async updateProgress(req, res) {
        try {
            const { progress } = req.body;

            const query = `
                UPDATE user_trainings
                SET progress = ?,
                    last_accessed_at = NOW()
                WHERE user_id = ?
                    AND training_id = ?
            `;

            await connection.execute(query, [progress, req.userId, req.params.id]);
            res.json({ message: 'Progresso atualizado com sucesso' });
        } catch (error) {
            console.error('Erro ao atualizar progresso:', error);
            res.status(500).json({ message: 'Erro ao atualizar progresso' });
        }
    }

    // Matricula o usuário em um treinamento
    static async enrollTraining(req, res) {
        try {
            // Verifica se o treinamento existe e está publicado
            const [training] = await connection.execute(
                'SELECT id FROM trainings WHERE id = ? AND status = "published"', [req.params.id]
            );

            if (training.length === 0) {
                return res.status(404).json({ message: 'Treinamento não encontrado' });
            }

            // Verifica se o usuário já está matriculado
            const [enrollment] = await connection.execute(
                'SELECT id FROM user_trainings WHERE user_id = ? AND training_id = ?', [req.userId, req.params.id]
            );

            if (enrollment.length > 0) {
                return res.status(400).json({ message: 'Usuário já está matriculado neste treinamento' });
            }

            // Matricula o usuário
            await connection.execute(
                `INSERT INTO user_trainings (user_id, training_id, progress, last_accessed_at)
                 VALUES (?, ?, 0, NOW())`, [req.userId, req.params.id]
            );

            res.status(201).json({ message: 'Matrícula realizada com sucesso' });
        } catch (error) {
            console.error('Erro ao matricular usuário:', error);
            res.status(500).json({ message: 'Erro ao matricular usuário' });
        }
    }
}

module.exports = UserTrainingsController;