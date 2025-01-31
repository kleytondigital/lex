const express = require('express');
const router = express.Router();
const UserTrainingsController = require('../../controllers/UserTrainingsController');

// Debug middleware
router.use((req, res, next) => {
    console.log('Trainings route accessed:', {
        method: req.method,
        path: req.path,
        fullUrl: req.originalUrl,
        params: req.params,
        userId: req.userId
    });
    next();
});

// Listar treinamentos em progresso
router.get('/in-progress', UserTrainingsController.getInProgress);

// Listar treinamentos bloqueados
router.get('/locked', UserTrainingsController.getLocked);

// Listar treinamentos disponíveis
router.get('/available', UserTrainingsController.getAvailable);

// Buscar detalhes de um treinamento específico
router.get('/:id', UserTrainingsController.getById);

// Buscar módulos de um treinamento
router.get('/:id/modules', UserTrainingsController.getModules);

// Buscar detalhes de um módulo específico
router.get('/:id/modules/:moduleId', UserTrainingsController.getModuleDetails);

// Buscar detalhes de uma aula específica
router.get('/:id/modules/:moduleId/lessons/:lessonId', UserTrainingsController.getLessonDetails);

// Registrar progresso em uma aula
router.post('/:id/progress', UserTrainingsController.updateProgress);

// Matricular usuário em um treinamento
router.post('/:id/enroll', UserTrainingsController.enrollTraining);

module.exports = router;