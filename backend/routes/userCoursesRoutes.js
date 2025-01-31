const express = require('express');
const router = express.Router();
const UserTrainingsController = require('../controllers/UserTrainingsController');

router.get('/in-progress', UserTrainingsController.getInProgress);
router.get('/locked', UserTrainingsController.getLocked);
router.get('/available', UserTrainingsController.getAvailable);

module.exports = router;