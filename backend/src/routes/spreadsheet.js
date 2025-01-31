const express = require('express');
const router = express.Router();
const authMiddleware = require('../middlewares/auth');
const SpreadsheetController = require('../controllers/SpreadsheetController');

// Todas as rotas precisam de autenticação
router.use(authMiddleware);

// Rotas para Planilhas
router.post('/connect', SpreadsheetController.connect);
router.post('/sync', SpreadsheetController.sync);
router.get('/status', SpreadsheetController.getStatus);
router.delete('/disconnect', SpreadsheetController.disconnect);

module.exports = router;