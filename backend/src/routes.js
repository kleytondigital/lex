const express = require('express');
const authMiddleware = require('./middlewares/auth');
const LandingPageController = require('./controllers/LandingPageController');

const routes = express.Router();

// ... outras rotas existentes ...

// Rotas de Landing Pages (protegidas)
routes.use('/landpages', authMiddleware);
routes.get('/landpages', LandingPageController.index);
routes.post('/landpages', LandingPageController.store);
routes.get('/landpages/:id', LandingPageController.show);
routes.put('/landpages/:id', LandingPageController.update);
routes.delete('/landpages/:id', LandingPageController.destroy);

module.exports = routes;