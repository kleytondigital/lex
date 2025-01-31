require('dotenv').config();

module.exports = {
    port: process.env.PORT || 5000,
    database: {
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD || '',
        database: process.env.DB_NAME || 'lex_db'
    },
    jwt: {
        secret: process.env.JWT_SECRET || 'sua_chave_secreta',
        expiresIn: process.env.JWT_EXPIRES_IN || '24h'
    },

    // Configurações de email
    email: {
        host: process.env.EMAIL_HOST,
        port: process.env.EMAIL_PORT,
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
        from: process.env.EMAIL_FROM || 'noreply@lex.com',
    },

    // Configurações do Mercado Pago
    mercadoPago: {
        accessToken: process.env.MP_ACCESS_TOKEN,
        publicKey: process.env.MP_PUBLIC_KEY
    },

    // URLs
    frontendUrl: process.env.FRONTEND_URL || 'http://lex.aoseudispor.com.br:3001',
    apiUrl: process.env.API_URL || 'http://lex.aoseudispor.com.br:5000'
};