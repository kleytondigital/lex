const db = require('../src/config/database');

class UserTrainingsController {
    async getInProgress(req, res) {
        try {
            const userId = req.userId;
            const [trainings] = await db.execute(`
                SELECT 
                    t.id,
                    t.name,
                    t.description,
                    t.thumbnail,
                    t.category,
                    t.price,
                    ut.progress,
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
                JOIN user_trainings ut ON t.id = ut.training_id
                WHERE ut.user_id = ?
                AND ut.deleted_at IS NULL
                AND t.deleted_at IS NULL
                ORDER BY ut.last_accessed_at DESC
            `, [userId]);

            res.json(trainings);
        } catch (error) {
            console.error('Erro ao buscar treinamentos em progresso:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async getById(req, res) {
        try {
            const { id } = req.params;
            const userId = req.userId;

            const [trainings] = await db.execute(`
                SELECT 
                    t.id,
                    t.name,
                    t.description,
                    t.thumbnail,
                    t.category,
                    t.price,
                    t.status,
                    COALESCE(ut.progress, 0) as progress,
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
                LEFT JOIN user_trainings ut ON t.id = ut.training_id AND ut.user_id = ?
                WHERE t.id = ?
                AND t.deleted_at IS NULL
                AND t.status = 'published'
            `, [userId, id]);

            if (!trainings.length) {
                return res.status(404).json({ error: 'Treinamento não encontrado' });
            }

            res.json(trainings[0]);
        } catch (error) {
            console.error('Erro ao buscar treinamento:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async getModules(req, res) {
        try {
            const { id } = req.params;
            const userId = req.userId;

            // Primeiro verifica se o treinamento existe e está publicado
            const [training] = await db.execute(
                'SELECT id FROM trainings WHERE id = ? AND status = "published" AND deleted_at IS NULL', [id]
            );

            if (!training.length) {
                return res.status(404).json({ error: 'Treinamento não encontrado' });
            }

            // Busca os módulos
            const [modules] = await db.execute(`
                SELECT 
                    tm.id,
                    tm.title,
                    tm.description,
                    tm.order_index
                FROM training_modules tm
                WHERE tm.training_id = ?
                AND tm.deleted_at IS NULL
                ORDER BY tm.order_index
            `, [id]);

            // Busca as aulas para cada módulo
            for (let module of modules) {
                const [lessons] = await db.execute(`
                    SELECT 
                        id,
                        title,
                        description,
                        content_type,
                        duration,
                        order_index
                    FROM lessons
                    WHERE module_id = ?
                    AND deleted_at IS NULL
                    ORDER BY order_index
                `, [module.id]);

                module.lessons = lessons;
            }

            res.json(modules);
        } catch (error) {
            console.error('Erro ao buscar módulos:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async getLocked(req, res) {
        try {
            const userId = req.userId;
            const [trainings] = await db.execute(`
                SELECT 
                    t.id,
                    t.name,
                    t.description,
                    t.thumbnail,
                    t.category,
                    t.price,
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
                WHERE t.id NOT IN (
                    SELECT training_id 
                    FROM user_trainings 
                    WHERE user_id = ?
                    AND deleted_at IS NULL
                )
                AND t.deleted_at IS NULL
                AND t.status = 'published'
                ORDER BY t.created_at DESC
            `, [userId]);

            res.json(trainings);
        } catch (error) {
            console.error('Erro ao buscar treinamentos bloqueados:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async getAvailable(req, res) {
        try {
            const userId = req.userId;
            const [trainings] = await db.execute(`
                SELECT 
                    t.id,
                    t.name,
                    t.description,
                    t.thumbnail,
                    t.category,
                    t.price,
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
                AND t.status = 'published'
                AND t.id NOT IN (
                    SELECT training_id 
                    FROM user_trainings 
                    WHERE user_id = ?
                    AND deleted_at IS NULL
                )
                ORDER BY t.created_at DESC
            `, [userId]);

            res.json(trainings);
        } catch (error) {
            console.error('Erro ao buscar treinamentos disponíveis:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async enrollTraining(req, res) {
        try {
            const { id } = req.params;
            const userId = req.userId;

            // Verifica se o treinamento existe e está publicado
            const [training] = await db.execute(
                'SELECT id FROM trainings WHERE id = ? AND status = "published" AND deleted_at IS NULL', [id]
            );

            if (!training.length) {
                return res.status(404).json({ error: 'Treinamento não encontrado' });
            }

            // Verifica se o usuário já está matriculado
            const [existingEnrollment] = await db.execute(
                'SELECT id FROM user_trainings WHERE user_id = ? AND training_id = ? AND deleted_at IS NULL', [userId, id]
            );

            if (existingEnrollment.length) {
                return res.status(400).json({ error: 'Usuário já está matriculado neste treinamento' });
            }

            // Registra o usuário no treinamento
            await db.execute(`
                INSERT INTO user_trainings (user_id, training_id, progress, created_at, last_accessed_at)
                VALUES (?, ?, 0, NOW(), NOW())
            `, [userId, id]);

            res.json({ message: 'Matrícula realizada com sucesso' });
        } catch (error) {
            console.error('Erro ao matricular usuário:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async getModuleDetails(req, res) {
        try {
            const { id: trainingId, moduleId } = req.params;
            const userId = req.userId;

            // Verifica se o usuário tem acesso ao treinamento
            const [enrollment] = await db.execute(
                'SELECT id FROM user_trainings WHERE user_id = ? AND training_id = ? AND deleted_at IS NULL', [userId, trainingId]
            );

            if (!enrollment.length) {
                return res.status(403).json({ error: 'Usuário não tem acesso a este treinamento' });
            }

            // Busca detalhes do módulo e suas aulas
            const [modules] = await db.execute(`
                SELECT 
                    tm.id,
                    tm.title,
                    tm.description,
                    tm.order_index
                FROM training_modules tm
                WHERE tm.id = ?
                AND tm.training_id = ?
                AND tm.deleted_at IS NULL
            `, [moduleId, trainingId]);

            if (!modules.length) {
                return res.status(404).json({ error: 'Módulo não encontrado' });
            }

            const module = modules[0];

            // Busca as aulas do módulo
            const [lessons] = await db.execute(`
                SELECT 
                    id,
                    title,
                    description,
                    content_type,
                    content,
                    video_url,
                    duration,
                    order_index
                FROM lessons
                WHERE module_id = ?
                AND deleted_at IS NULL
                ORDER BY order_index
            `, [moduleId]);

            module.lessons = lessons;

            res.json(module);
        } catch (error) {
            console.error('Erro ao buscar detalhes do módulo:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async getLessonDetails(req, res) {
        try {
            const { id: trainingId, moduleId, lessonId } = req.params;
            const userId = req.userId;

            // Verifica se o usuário tem acesso ao treinamento
            const [enrollment] = await db.execute(
                'SELECT id FROM user_trainings WHERE user_id = ? AND training_id = ? AND deleted_at IS NULL', [userId, trainingId]
            );

            if (!enrollment.length) {
                return res.status(403).json({ error: 'Usuário não tem acesso a este treinamento' });
            }

            // Busca detalhes da aula
            const [lessons] = await db.execute(`
                SELECT 
                    l.id,
                    l.title,
                    l.description,
                    l.content_type,
                    l.content,
                    l.video_url,
                    l.duration,
                    l.order_index,
                    tm.title as module_title
                FROM lessons l
                JOIN training_modules tm ON tm.id = l.module_id
                WHERE l.id = ?
                AND l.module_id = ?
                AND tm.training_id = ?
                AND l.deleted_at IS NULL
            `, [lessonId, moduleId, trainingId]);

            if (!lessons.length) {
                return res.status(404).json({ error: 'Aula não encontrada' });
            }

            res.json(lessons[0]);
        } catch (error) {
            console.error('Erro ao buscar detalhes da aula:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async updateProgress(req, res) {
        try {
            const { id: trainingId } = req.params;
            const { module_id: moduleId, lesson_id: lessonId } = req.body;
            const userId = req.userId;

            // Verifica se o usuário tem acesso ao treinamento
            const [enrollment] = await db.execute(
                'SELECT id FROM user_trainings WHERE user_id = ? AND training_id = ? AND deleted_at IS NULL', [userId, trainingId]
            );

            if (!enrollment.length) {
                return res.status(403).json({ error: 'Usuário não tem acesso a este treinamento' });
            }

            // Registra o progresso da aula
            await db.execute(`
                INSERT INTO lesson_progress 
                    (user_id, training_id, module_id, lesson_id, completed_at)
                VALUES (?, ?, ?, ?, NOW())
                ON DUPLICATE KEY UPDATE completed_at = NOW()
            `, [userId, trainingId, moduleId, lessonId]);

            // Calcula o novo progresso geral do treinamento
            const [totalLessons] = await db.execute(`
                SELECT COUNT(DISTINCT l.id) as total
                FROM lessons l
                JOIN training_modules tm ON tm.id = l.module_id
                WHERE tm.training_id = ?
                AND tm.deleted_at IS NULL
                AND l.deleted_at IS NULL
            `, [trainingId]);

            const [completedLessons] = await db.execute(`
                SELECT COUNT(DISTINCT lp.lesson_id) as completed
                FROM lesson_progress lp
                WHERE lp.user_id = ?
                AND lp.training_id = ?
            `, [userId, trainingId]);

            const progress = Math.round((completedLessons[0].completed / totalLessons[0].total) * 100);

            // Atualiza o progresso no user_trainings
            await db.execute(`
                UPDATE user_trainings
                SET progress = ?, last_accessed_at = NOW()
                WHERE user_id = ? AND training_id = ?
            `, [progress, userId, trainingId]);

            res.json({ message: 'Progresso atualizado com sucesso', progress });
        } catch (error) {
            console.error('Erro ao atualizar progresso:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }
}

module.exports = new UserTrainingsController();