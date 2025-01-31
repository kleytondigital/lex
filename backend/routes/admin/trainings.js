const express = require('express');
const router = express.Router();
const TrainingController = require('../../controllers/TrainingController');
const trainingModulesRouter = require('./training-modules');

// Rotas de módulos (nested routes)
router.use('/:training_id/modules', trainingModulesRouter);

// Rotas de treinamentos
router.get('/', TrainingController.list);
router.post('/', TrainingController.validate(), TrainingController.create);
router.get('/:id', TrainingController.getById);
router.put('/:id', TrainingController.validate(), TrainingController.update);
router.patch('/:id/status', TrainingController.updateStatus);

module.exports = router;