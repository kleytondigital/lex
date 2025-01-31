const express = require('express');
const router = express.Router({ mergeParams: true }); // Para acessar params da rota pai
const TrainingModuleController = require('../../controllers/TrainingModuleController');
const lessonsRouter = require('./lessons');

// Rotas de aulas (nested routes)
router.use('/:module_id/lessons', lessonsRouter);

// Listar módulos de um treinamento
router.get('/', TrainingModuleController.list);

// Obter detalhes de um módulo específico
router.get('/:id', TrainingModuleController.getById);

// Criar novo módulo
router.post('/', TrainingModuleController.validate(), TrainingModuleController.create);

// Atualizar módulo
router.put('/:id', TrainingModuleController.validate(), TrainingModuleController.update);

// Excluir módulo
router.delete('/:id', TrainingModuleController.delete);

// Reordenar módulos
router.post('/reorder', TrainingModuleController.reorder);

module.exports = router;