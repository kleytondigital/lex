const express = require('express');
const cors = require('cors');
const routes = require('./routes');

const app = express();

// Configuração do CORS
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://lex.aoseudispor.com.br:5173',
    credentials: true
}));

// Parse JSON payloads
app.use(express.json());

// Adiciona o prefixo /api para todas as rotas
app.use('/api', routes);

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Erro interno do servidor' });
});

module.exports = app;