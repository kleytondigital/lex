const User = require('../../models/User');
const Course = require('../../models/Course');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const config = require('../config/config');

const userController = {
    // Obter estatísticas do usuário
    async getUserStats(req, res) {
        try {
            const stats = await User.getStats(req.user.id);
            res.json(stats || {
                totalCourses: 0,
                completedCourses: 0,
                studyHours: 0,
                certificates: 0
            });
        } catch (error) {
            console.error('Erro ao buscar estatísticas:', error);
            res.status(200).json({
                totalCourses: 0,
                completedCourses: 0,
                studyHours: 0,
                certificates: 0
            });
        }
    },

    // Obter cursos completados
    async getCompletedCourses(req, res) {
        try {
            const courses = await User.getCompletedCourses(req.user.id);
            res.json(courses || []);
        } catch (error) {
            console.error('Erro ao buscar cursos concluídos:', error);
            res.status(200).json([]); // Retorna array vazio em caso de erro
        }
    },

    // Obter perfil do usuário
    async getProfile(req, res) {
        try {
            const user = await User.findById(req.user.id);
            if (!user) {
                return res.status(404).json({ error: 'Usuário não encontrado' });
            }

            // Remove a senha e outros campos sensíveis
            const { password, ...userWithoutPassword } = user;
            res.json(userWithoutPassword);
        } catch (error) {
            console.error('Erro ao buscar perfil:', error);
            res.status(200).json({
                id: req.user.id,
                name: 'Usuário',
                email: '',
                avatar: null,
                createdAt: new Date()
            });
        }
    },

    async getDashboardStats(req, res) {
        try {
            const stats = {
                users: 0,
                courses: 0,
                activeUsers: 0,
                revenue: 0,
                usersChange: "+0%",
                coursesChange: "+0",
                activeUsersChange: "+0%",
                revenueChange: "+0%"
            };

            // TODO: Implementar lógica para buscar estatísticas reais do banco

            res.json(stats);
        } catch (error) {
            console.error('Erro ao buscar estatísticas do dashboard:', error);
            res.status(500).json({ message: 'Erro ao buscar estatísticas do dashboard' });
        }
    },

    // Registro de usuário
    async register(req, res) {
        try {
            const { email, digitalName } = req.body;

            // Verificar se email já existe
            const existingUser = await User.findByEmail(email);
            if (existingUser) {
                return res.status(400).json({ error: 'Email já cadastrado' });
            }

            // Verificar se nome digital está disponível
            const digitalNameAvailable = await User.checkDigitalNameAvailable(digitalName);
            if (!digitalNameAvailable) {
                return res.status(400).json({ error: 'Nome digital já está em uso' });
            }

            const userId = await User.create(req.body);
            res.status(201).json({ id: userId });
        } catch (error) {
            console.error('Erro ao registrar usuário:', error);
            res.status(500).json({ error: 'Erro ao criar usuário' });
        }
    },

    // Login de usuário
    async login(req, res) {
        try {
            const { email, password } = req.body;

            const user = await User.findByEmail(email);
            if (!user) {
                return res.status(401).json({ error: 'Credenciais inválidas' });
            }

            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                return res.status(401).json({ error: 'Credenciais inválidas' });
            }

            const token = jwt.sign({ id: user.id }, config.jwtSecret, { expiresIn: '24h' });

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
            console.error('Erro no login:', error);
            res.status(500).json({ error: 'Erro ao realizar login' });
        }
    },

    // Recuperação de senha
    async forgotPassword(req, res) {
        try {
            const { email } = req.body;
            const user = await User.findByEmail(email);

            if (!user) {
                return res.status(404).json({ error: 'Usuário não encontrado' });
            }

            // TODO: Implementar lógica de envio de email
            res.json({ message: 'Email de recuperação enviado' });
        } catch (error) {
            console.error('Erro na recuperação de senha:', error);
            res.status(500).json({ error: 'Erro ao processar recuperação de senha' });
        }
    },

    // Reset de senha
    async resetPassword(req, res) {
        try {
            const { token, password } = req.body;
            // TODO: Implementar validação do token e reset de senha
            res.json({ message: 'Senha alterada com sucesso' });
        } catch (error) {
            console.error('Erro no reset de senha:', error);
            res.status(500).json({ error: 'Erro ao resetar senha' });
        }
    }
};

module.exports = userController;