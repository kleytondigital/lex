const express = require('express');
const router = express.Router();
const AdminTrainingsController = require('../controllers/AdminTrainingsController');

// ... existing routes ...

// Atualizar status do treinamento
router.patch('/:id/status', AdminTrainingsController.updateStatus);

module.exports = router;