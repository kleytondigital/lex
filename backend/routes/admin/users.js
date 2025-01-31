const express = require('express');
const router = express.Router();
const db = require('../../src/config/database');

// Listar todos os usuários
router.get('/', async(req, res) => {
    try {
        const [users] = await db.execute(`
            SELECT 
                id,
                name,
                email,
                status,
                role,
                avatar,
                created_at as createdAt,
                (
                    SELECT COUNT(*)
                    FROM user_trainings ut
                    WHERE ut.user_id = users.id
                ) as enrolledCourses
            FROM users
            WHERE deleted_at IS NULL
            ORDER BY created_at DESC
        `);

        res.json({ users });
    } catch (error) {
        console.error('Erro ao buscar usuários:', error);
        res.status(500).json({ error: 'Erro ao buscar usuários' });
    }
});

// Criar usuário
router.post('/', async(req, res) => {
    try {
        const { name, email, password, role = 'user' } = req.body;

        // Verificar se o email já existe
        const [existingUser] = await db.execute(
            'SELECT id FROM users WHERE email = ?', [email]
        );

        if (existingUser.length > 0) {
            return res.status(400).json({ error: 'Email já cadastrado' });
        }

        // Criar o usuário
        const [result] = await db.execute(
            'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)', [name, email, password, role]
        );

        res.status(201).json({
            id: result.insertId,
            name,
            email,
            role
        });
    } catch (error) {
        console.error('Erro ao criar usuário:', error);
        res.status(500).json({ error: 'Erro ao criar usuário' });
    }
});

// Buscar usuário por ID
router.get('/:id', async(req, res) => {
    try {
        const [users] = await db.execute(
            'SELECT id, name, email, role, status, created_at FROM users WHERE id = ? AND deleted_at IS NULL', [req.params.id]
        );

        if (users.length === 0) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }

        res.json(users[0]);
    } catch (error) {
        console.error('Erro ao buscar usuário:', error);
        res.status(500).json({ error: 'Erro ao buscar usuário' });
    }
});

// Atualizar usuário
router.put('/:id', async(req, res) => {
    try {
        const { name, email, role, status } = req.body;
        const { id } = req.params;

        await db.execute(
            'UPDATE users SET name = ?, email = ?, role = ?, status = ? WHERE id = ?', [name, email, role, status, id]
        );

        res.json({ message: 'Usuário atualizado com sucesso' });
    } catch (error) {
        console.error('Erro ao atualizar usuário:', error);
        res.status(500).json({ error: 'Erro ao atualizar usuário' });
    }
});

// Deletar usuário (soft delete)
router.delete('/:id', async(req, res) => {
    try {
        const { id } = req.params;
        const now = new Date().toISOString().slice(0, 19).replace('T', ' ');

        await db.execute(
            'UPDATE users SET deleted_at = ? WHERE id = ?', [now, id]
        );

        res.json({ message: 'Usuário deletado com sucesso' });
    } catch (error) {
        console.error('Erro ao deletar usuário:', error);
        res.status(500).json({ error: 'Erro ao deletar usuário' });
    }
});

module.exports = router;