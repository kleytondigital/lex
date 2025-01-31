const express = require('express');
const router = express.Router();
const UserCoursesController = require('../../controllers/UserCoursesController');

// Listar cursos em progresso
router.get('/in-progress', UserCoursesController.getInProgress);

// Listar cursos bloqueados
router.get('/locked', UserCoursesController.getLocked);

module.exports = router;