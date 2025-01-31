const db = require('../src/config/database');

class AdminDashboardController {
    async getStats(req, res) {
        try {
            // Total de treinamentos
            const [trainings] = await db.execute(`
                SELECT 
                    COUNT(*) as total,
                    COUNT(CASE WHEN status = 'published' THEN 1 END) as published
                FROM trainings 
                WHERE deleted_at IS NULL
            `);

            // Total de usuários
            const [users] = await db.execute(`
                SELECT COUNT(*) as total
                FROM users 
                WHERE deleted_at IS NULL
            `);

            // Total de módulos
            const [modules] = await db.execute(`
                SELECT COUNT(*) as total
                FROM training_modules 
                WHERE deleted_at IS NULL
            `);

            // Total de aulas
            const [lessons] = await db.execute(`
                SELECT COUNT(*) as total
                FROM lessons 
                WHERE deleted_at IS NULL
            `);

            res.json({
                trainings: {
                    total: trainings[0].total,
                    published: trainings[0].published
                },
                users: users[0].total,
                modules: modules[0].total,
                lessons: lessons[0].total
            });
        } catch (error) {
            console.error('Erro ao buscar estatísticas:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }
}

module.exports = new AdminDashboardController();