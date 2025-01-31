const express = require('express');
const router = express.Router();
const authMiddleware = require('../middlewares/auth');
const LeadController = require('../controllers/LeadController');

// Todas as rotas precisam de autenticação
router.use(authMiddleware);

// Rotas para Leads
router.get('/', LeadController.index);
router.get('/:id', LeadController.show);
router.post('/', LeadController.store);
router.put('/:id', LeadController.update);
router.delete('/:id', LeadController.destroy);

// Rotas para exportação
router.get('/export/excel', LeadController.exportToExcel);
router.get('/export/csv', LeadController.exportToCSV);

// Rotas para filtros e busca
router.get('/search', LeadController.search);
router.get('/filter', LeadController.filter);

// Rotas para estatísticas
router.get('/stats/overview', LeadController.getOverviewStats);
router.get('/stats/conversion', LeadController.getConversionStats);
router.get('/stats/source', LeadController.getSourceStats);

module.exports = router;