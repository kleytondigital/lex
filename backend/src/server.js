const express = require('express');
const cors = require('cors');
const config = require('./config/config');
const path = require('path');

// Importação das rotas
const authRoutes = require('./routes/auth');
const coursesRoutes = require('./routes/courses');
const adminRoutes = require('../routes/admin');
const userRoutes = require('./routes/users');
const landpagesRoutes = require('./routes/landpages');
const landpageRoutes = require('./routes/landpage');
const leadRoutes = require('./routes/leads');
const spreadsheetRoutes = require('./routes/spreadsheet');
const emailRoutes = require('./routes/email');
const userRouter = require('./routes/user');

const app = express();

// Configuração do CORS
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3001',
    credentials: true
}));

// Configuração do parser JSON com limite aumentado e tratamento de erro
app.use(express.json({ limit: '10mb' }));

// Middleware para tratar erros de JSON inválido
app.use((err, req, res, next) => {
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        console.error('JSON inválido:', err);
        return res.status(400).json({ error: 'JSON inválido na requisição' });
    }
    next();
});

// Serve static files from uploads directory
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

// Debug middleware
app.use((req, res, next) => {
    console.log('Request:', {
        method: req.method,
        path: req.path,
        fullUrl: req.originalUrl,
        body: req.body
    });
    next();
});

// Rotas públicas
app.use('/api/auth', authRoutes);
app.use('/api/p', landpageRoutes); // Landing pages de clientes
app.use('/api/c', landpageRoutes); // Landing pages de consultores

// Rotas protegidas
app.use('/api/admin/courses', coursesRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/user', userRouter); // Rotas de usuário (inclui produtos e pedidos)
app.use('/api/landpages', landpagesRoutes);
app.use('/api/leads', leadRoutes);
app.use('/api/spreadsheet', spreadsheetRoutes);
app.use('/api/email', emailRoutes);

// Tratamento de erros
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Erro interno do servidor' });
});

// Iniciar servidor
const PORT = process.env.PORT || 5001; // Alterado para 5001
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});