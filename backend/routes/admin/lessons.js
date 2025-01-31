const express = require('express');
const router = express.Router({ mergeParams: true }); // Para acessar params da rota pai
const LessonController = require('../../controllers/LessonController');

// Listar aulas de um módulo
router.get('/', LessonController.list);

// Obter detalhes de uma aula específica
router.get('/:id', LessonController.getById);

// Criar nova aula
router.post('/', LessonController.validate(), LessonController.create);

// Atualizar aula
router.put('/:id', LessonController.validate(), LessonController.update);

// Excluir aula
router.delete('/:id', LessonController.delete);

// Reordenar aulas
router.post('/reorder', LessonController.reorder);

module.exports = router;