const express = require('express');
const router = express.Router();
const courseController = require('../controllers/courseController');
const authMiddleware = require('../middlewares/auth');
const adminMiddleware = require('../middlewares/admin');
const Course = require('../../models/Course');

// Rotas públicas
router.get('/', courseController.getAllCourses);

// Rotas que requerem autenticação
router.use(authMiddleware);
router.get('/enrolled', courseController.getEnrolledCourses);

// Rota pública com parâmetro
router.get('/:id', courseController.getCourseById);

// Rotas de admin
router.post('/', adminMiddleware, async(req, res) => {
    try {
        const courseData = {
            title: req.body.title,
            description: req.body.description,
            instructor: req.body.instructor,
            thumbnail: req.body.thumbnail,
            price: req.body.type === 'free' ? 0 : req.body.price,
            type: req.body.type,
            category: req.body.category,
            duration: req.body.duration,
            level: req.body.level,
            requirements: req.body.requirements,
            learningGoals: req.body.learningGoals,
            modules: req.body.modules,
            createdBy: req.user.id
        };

        const courseId = await Course.create(courseData);
        res.status(201).json({ id: courseId, message: 'Curso criado com sucesso' });
    } catch (error) {
        console.error('Erro ao criar curso:', error);
        res.status(500).json({ error: 'Erro ao criar curso' });
    }
});

router.get('/', adminMiddleware, async(req, res) => {
    try {
        const courses = await Course.findAll();
        res.json(courses);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar cursos' });
    }
});

router.put('/:id', adminMiddleware, async(req, res) => {
    try {
        const updated = await Course.update(req.params.id, req.body);
        if (!updated) {
            return res.status(404).json({ error: 'Curso não encontrado' });
        }
        res.json({ message: 'Curso atualizado com sucesso' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao atualizar curso' });
    }
});

router.delete('/:id', adminMiddleware, async(req, res) => {
    try {
        const deleted = await Course.delete(req.params.id);
        if (!deleted) {
            return res.status(404).json({ error: 'Curso não encontrado' });
        }
        res.json({ message: 'Curso deletado com sucesso' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao deletar curso' });
    }
});

router.get('/recommended', courseController.getRecommendedCourses);

module.exports = router;