const db = require('../config/database');
const Course = require('../../models/Course');

const courseController = {
    // Listar todos os cursos
    async getAllCourses(req, res) {
        try {
            const [courses] = await db.query('SELECT * FROM courses WHERE status = "published"');
            res.json(courses);
        } catch (error) {
            res.status(500).json({ error: 'Erro ao buscar cursos' });
        }
    },

    // Obter um curso específico
    async getCourseById(req, res) {
        try {
            const [course] = await db.query('SELECT * FROM courses WHERE id = ?', [req.params.id]);
            if (course.length === 0) {
                return res.status(404).json({ error: 'Curso não encontrado' });
            }
            res.json(course[0]);
        } catch (error) {
            res.status(500).json({ error: 'Erro ao buscar curso' });
        }
    },

    // Criar um novo curso
    async createCourse(req, res) {
        try {
            const { name, description, instructor, category, duration, price } = req.body;
            const [result] = await db.query(
                'INSERT INTO courses (name, description, instructor, category, duration, price) VALUES (?, ?, ?, ?, ?, ?)', [name, description, instructor, category, duration, price]
            );
            res.status(201).json({ id: result.insertId, message: 'Curso criado com sucesso' });
        } catch (error) {
            res.status(500).json({ error: 'Erro ao criar curso' });
        }
    },

    // Atualizar um curso
    async updateCourse(req, res) {
        try {
            const { name, description, instructor, category, duration, price } = req.body;
            const [result] = await db.query(
                'UPDATE courses SET name = ?, description = ?, instructor = ?, category = ?, duration = ?, price = ? WHERE id = ?', [name, description, instructor, category, duration, price, req.params.id]
            );
            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'Curso não encontrado' });
            }
            res.json({ message: 'Curso atualizado com sucesso' });
        } catch (error) {
            res.status(500).json({ error: 'Erro ao atualizar curso' });
        }
    },

    // Deletar um curso
    async deleteCourse(req, res) {
        try {
            const [result] = await db.query('DELETE FROM courses WHERE id = ?', [req.params.id]);
            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'Curso não encontrado' });
            }
            res.json({ message: 'Curso deletado com sucesso' });
        } catch (error) {
            res.status(500).json({ error: 'Erro ao deletar curso' });
        }
    },

    // Obter cursos em que o usuário está matriculado
    async getEnrolledCourses(req, res) {
        try {
            const courses = await Course.getEnrolledByUser(req.user.id);
            res.json(courses || []);
        } catch (error) {
            console.error('Erro ao buscar cursos matriculados:', error);
            res.status(200).json([]);
        }
    },

    // Obter cursos recomendados
    async getRecommendedCourses(req, res) {
        try {
            const courses = await Course.getRecommended(req.user.id);
            res.json(courses || []);
        } catch (error) {
            console.error('Erro ao buscar cursos recomendados:', error);
            res.status(200).json([]);
        }
    },

    async getCompletedCourses(req, res) {
        try {
            const courses = await Course.getCompletedByUser(req.user.id);
            res.json(courses || []);
        } catch (error) {
            console.error('Erro ao buscar cursos concluídos:', error);
            res.status(200).json([]);
        }
    }
};

module.exports = courseController;