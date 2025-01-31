const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const authMiddleware = require('../middlewares/auth');
const profileMiddleware = require('../middlewares/profile');
const UserProductController = require('../controllers/UserProductController');

// Debug middleware
router.use((req, res, next) => {
    console.log('Users route accessed:', {
        method: req.method,
        path: req.path,
        fullUrl: req.originalUrl
    });
    next();
});

// Aplica o middleware de autenticação
router.use(authMiddleware);

// Rotas públicas
router.post('/register', userController.register);
router.post('/login', userController.login);
router.post('/forgot-password', userController.forgotPassword);
router.post('/reset-password', userController.resetPassword);

// Rotas protegidas
router.use('/stats', authMiddleware);
router.use('/profile', authMiddleware);
router.use('/completed-courses', authMiddleware);

router.get('/stats', userController.getUserStats);
router.get('/profile', userController.getProfile);
router.get('/completed-courses', userController.getCompletedCourses);
router.get('/products/available', UserProductController.getAvailable);

module.exports = router;