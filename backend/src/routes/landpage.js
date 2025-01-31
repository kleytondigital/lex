// Rotas para:
// - Configuração das landing pages
// - Upload de imagens
// - Gestão de leads

const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const authMiddleware = require('../middlewares/auth');
const landpageMiddleware = require('../middlewares/landpage');
const Landpage = require('../../models/Landpage');
const emailService = require('../services/emailService');
const spreadsheetService = require('../services/spreadsheetService');
const LandingPageController = require('../controllers/LandingPageController');
const LeadController = require('../controllers/LeadController');

// Rotas públicas para acessar landing pages por nome digital
router.get('/:digitalName', LandingPageController.getByDigitalName); // Landing pages de clientes
router.get('/:digitalName', LandingPageController.getByDigitalName); // Landing pages de consultores

// Configuração do Multer para upload de imagens
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/landpage/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
        cb(null, `${req.user.id}-${uniqueSuffix}${path.extname(file.originalname)}`);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);

        if (extname && mimetype) {
            return cb(null, true);
        }
        cb(new Error('Apenas imagens são permitidas!'));
    }
});

// Todas as rotas abaixo precisam de autenticação
router.use(authMiddleware);

// Buscar configurações das landing pages
router.get('/config', landpageMiddleware.validatePayment, async(req, res) => {
    try {
        const configs = await Landpage.getConfigsByUserId(req.user.id);
        res.json(configs);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar configurações' });
    }
});

// Atualizar configurações
router.put('/config/:id',
    landpageMiddleware.validatePayment,
    landpageMiddleware.validateAccess,
    async(req, res) => {
        try {
            await Landpage.updateConfig(req.params.id, req.body);
            res.json({ message: 'Configurações atualizadas com sucesso' });
        } catch (error) {
            res.status(500).json({ error: 'Erro ao atualizar configurações' });
        }
    }
);

// Upload de foto
router.post('/upload',
    landpageMiddleware.validatePayment,
    upload.single('photo'),
    async(req, res) => {
        try {
            if (!req.file) {
                return res.status(400).json({ error: 'Nenhuma imagem enviada' });
            }

            const photoUrl = `/uploads/consultants/${req.file.filename}`;
            await Landpage.updateConsultantPhoto(req.user.id, photoUrl);

            res.json({
                message: 'Foto atualizada com sucesso',
                photoUrl
            });
        } catch (error) {
            res.status(500).json({ error: 'Erro ao fazer upload da foto' });
        }
    }
);

// Registrar novo lead
router.post('/leads', async(req, res) => {
    try {
        const lead = await LeadController.store(req.body);
        const consultant = await LandingPageController.getConsultantByLandingPage(req.body.landing_page_id);

        // Enviar notificação por email
        if (consultant && consultant.email) {
            // Implementar notificação por email aqui
        }

        res.status(201).json(lead);
    } catch (error) {
        console.error('Error creating lead:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Listar leads do consultor
router.get('/leads',
    landpageMiddleware.validatePayment,
    async(req, res) => {
        try {
            const leads = await Landpage.getLeadsByConsultantId(req.user.id);
            res.json(leads);
        } catch (error) {
            res.status(500).json({ error: 'Erro ao buscar leads' });
        }
    }
);

// Rotas para Landing Pages
router.get('/', LandingPageController.index);
router.post('/', LandingPageController.store);
router.get('/:id', LandingPageController.show);
router.put('/:id', LandingPageController.update);
router.delete('/:id', LandingPageController.destroy);

// Rotas para gerenciamento de mídia da landing page
router.post('/:id/media', upload.single('file'), LandingPageController.uploadMedia);
router.delete('/:id/media/:mediaId', LandingPageController.deleteMedia);

// Rotas para publicação
router.put('/:id/publish', LandingPageController.publish);
router.put('/:id/unpublish', LandingPageController.unpublish);

// Rota para duplicar landing page
router.post('/:id/duplicate', LandingPageController.duplicate);

// Rota para estatísticas
router.get('/:id/stats', LandingPageController.getStats);

module.exports = router;