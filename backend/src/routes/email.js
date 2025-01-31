const express = require('express');
const router = express.Router();
const authMiddleware = require('../middlewares/auth');
const EmailController = require('../controllers/EmailController');

// Todas as rotas precisam de autenticação
router.use(authMiddleware);

// Rotas para Email
router.post('/send', EmailController.send);
router.post('/send-bulk', EmailController.sendBulk);
router.get('/templates', EmailController.getTemplates);
router.post('/templates', EmailController.createTemplate);
router.put('/templates/:id', EmailController.updateTemplate);
router.delete('/templates/:id', EmailController.deleteTemplate);

module.exports = router;