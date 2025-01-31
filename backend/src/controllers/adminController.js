const db = require('../config/database');

const adminController = {
    // Obter estatísticas do sistema
    async getStats(req, res) {
        try {
            const [userCount] = await db.query('SELECT COUNT(*) as total FROM users WHERE role = "user"');
            const [courseCount] = await db.query('SELECT COUNT(*) as total FROM courses');
            const [activeUsers] = await db.query('SELECT COUNT(*) as total FROM users WHERE status = "active"');

            res.json({
                users: userCount[0].total,
                courses: courseCount[0].total,
                activeUsers: activeUsers[0].total
            });
        } catch (error) {
            res.status(500).json({ error: 'Erro ao buscar estatísticas' });
        }
    },

    // Listar todos os usuários
    async getUsers(req, res) {
        try {
            const [users] = await db.query('SELECT id, name, email, role, status, created_at FROM users');
            res.json(users);
        } catch (error) {
            res.status(500).json({ error: 'Erro ao buscar usuários' });
        }
    },

    // Atualizar status do usuário
    async updateUserStatus(req, res) {
        try {
            const { id } = req.params;
            const { status } = req.body;

            const [result] = await db.query(
                'UPDATE users SET status = ? WHERE id = ?', [status, id]
            );

            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'Usuário não encontrado' });
            }

            res.json({ message: 'Status atualizado com sucesso' });
        } catch (error) {
            res.status(500).json({ error: 'Erro ao atualizar status' });
        }
    },

    // Obter configurações do sistema
    async getSettings(req, res) {
        try {
            const [settings] = await db.query('SELECT * FROM settings ORDER BY id DESC LIMIT 1');
            res.json(settings[0]);
        } catch (error) {
            res.status(500).json({ error: 'Erro ao buscar configurações' });
        }
    },

    // Atualizar configurações do sistema
    async updateSettings(req, res) {
        try {
            const {
                allow_registration,
                require_email_verification,
                max_file_size,
                supported_file_types,
                smtp_settings,
                payment_gateway
            } = req.body;

            const [result] = await db.query(
                `UPDATE settings SET 
                allow_registration = ?,
                require_email_verification = ?,
                max_file_size = ?,
                supported_file_types = ?,
                smtp_settings = ?,
                payment_gateway = ?
                WHERE id = 1`, [
                    allow_registration,
                    require_email_verification,
                    max_file_size,
                    JSON.stringify(supported_file_types),
                    JSON.stringify(smtp_settings),
                    JSON.stringify(payment_gateway)
                ]
            );

            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'Configurações não encontradas' });
            }

            res.json({ message: 'Configurações atualizadas com sucesso' });
        } catch (error) {
            res.status(500).json({ error: 'Erro ao atualizar configurações' });
        }
    }
};

module.exports = adminController;