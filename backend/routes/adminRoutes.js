const express = require('express');
const router = express.Router();
const AdminTrainingController = require('../controllers/AdminTrainingController');

// Rotas de treinamentos
router.get('/trainings', AdminTrainingController.list);
router.post('/trainings', AdminTrainingController.create);
router.get('/trainings/:id', AdminTrainingController.getById);
router.delete('/trainings/:id', AdminTrainingController.delete);
router.patch('/trainings/:id/status', AdminTrainingController.updateStatus);

module.exports = router;