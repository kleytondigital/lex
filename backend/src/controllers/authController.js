const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const connection = require('../config/database');
const config = require('../config/config');

const authController = {
    async login(req, res) {
        console.log('AuthController.login called');
        try {
            const { email, password } = req.body;

            // Validar dados
            if (!email || !password) {
                return res.status(400).json({ message: 'Email e senha são obrigatórios' });
            }

            // Buscar usuário
            const [users] = await connection.execute(
                'SELECT * FROM users WHERE email = ? AND status = "active"', [email]
            );

            if (users.length === 0) {
                return res.status(401).json({ message: 'Credenciais inválidas' });
            }

            const user = users[0];

            // Verificar senha
            const isValidPassword = await bcrypt.compare(password, user.password);
            if (!isValidPassword) {
                return res.status(401).json({ message: 'Credenciais inválidas' });
            }

            // Gerar token JWT
            const token = jwt.sign({
                    userId: user.id,
                    role: user.role
                },
                process.env.JWT_SECRET, { expiresIn: '24h' }
            );

            // Retornar resposta
            res.json({
                token,
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    role: user.role
                }
            });
        } catch (error) {
            console.error('Erro ao fazer login:', error);
            res.status(500).json({ message: 'Erro ao fazer login' });
        }
    },

    async register(req, res) {
        console.log('AuthController.register called');
        try {
            const { name, email, password } = req.body;

            // Validar dados
            if (!name || !email || !password) {
                return res.status(400).json({ message: 'Todos os campos são obrigatórios' });
            }

            // Verificar se o email já está em uso
            const [existingUsers] = await connection.execute(
                'SELECT id FROM users WHERE email = ?', [email]
            );

            if (existingUsers.length > 0) {
                return res.status(400).json({ message: 'Este email já está em uso' });
            }

            // Criptografar a senha
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);

            // Criar o usuário
            const [result] = await connection.execute(
                `INSERT INTO users (name, email, password, role, status, created_at) 
                 VALUES (?, ?, ?, 'user', 'active', NOW())`, [name, email, hashedPassword]
            );

            // Gerar token JWT
            const token = jwt.sign({
                    userId: result.insertId,
                    role: 'user'
                },
                process.env.JWT_SECRET, { expiresIn: '24h' }
            );

            // Retornar resposta
            res.status(201).json({
                message: 'Usuário registrado com sucesso',
                token,
                user: {
                    id: result.insertId,
                    name,
                    email,
                    role: 'user'
                }
            });
        } catch (error) {
            console.error('Erro ao registrar usuário:', error);
            res.status(500).json({ message: 'Erro ao registrar usuário' });
        }
    },

    async me(req, res) {
        try {
            const [users] = await connection.query(
                'SELECT id, name, email, digital_name, role FROM users WHERE id = ?', [req.userId]
            );

            if (users.length === 0) {
                return res.status(404).json({ error: 'Usuário não encontrado' });
            }

            res.json(users[0]);
        } catch (error) {
            console.error('Erro ao buscar usuário:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }
};

module.exports = authController;