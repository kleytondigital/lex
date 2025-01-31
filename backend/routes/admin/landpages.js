const express = require('express');
const router = express.Router();

// TODO: Implementar LandingPageController
router.get('/', (req, res) => {
    res.json({ message: 'Lista de landing pages' });
});

router.post('/', (req, res) => {
    res.json({ message: 'Criar landing page' });
});

router.get('/:id', (req, res) => {
    res.json({ message: 'Detalhes da landing page' });
});

router.put('/:id', (req, res) => {
    res.json({ message: 'Atualizar landing page' });
});

router.delete('/:id', (req, res) => {
    res.json({ message: 'Deletar landing page' });
});

module.exports = router;