const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const authMiddleware = require('../middlewares/auth');
const LandingPageController = require('../controllers/LandingPageController');

// Criar pasta temporária se não existir
const tempDir = path.join(process.cwd(), 'temp');
if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir, { recursive: true });
}

// Configuração do Multer para upload de imagens
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, tempDir);
    },
    filename: (req, file, cb) => {
        // Usar um nome temporário para o arquivo
        const tempFilename = `temp-${Date.now()}${path.extname(file.originalname)}`;
        cb(null, tempFilename);
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

// Todas as rotas precisam de autenticação
router.use(authMiddleware);

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

// Rotas de configuração
router.get('/:id/config', LandingPageController.getConfig);
router.put('/:id/config', LandingPageController.updateConfig);

// Add photo upload route
router.post('/upload-photo', authMiddleware, upload.single('photo'), LandingPageController.uploadPhoto);

module.exports = router;