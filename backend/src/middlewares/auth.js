const jwt = require('jsonwebtoken');
const config = require('../config/config');

module.exports = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader) {
            return res.status(401).json({ error: 'Token não fornecido' });
        }

        const [, token] = authHeader.split(' ');

        if (!token) {
            return res.status(401).json({ error: 'Token não fornecido' });
        }

        try {
            const decoded = jwt.verify(token, config.jwt.secret);
            req.userId = decoded.id;
            req.userRole = decoded.role;
            return next();
        } catch (error) {
            console.error('Erro ao verificar token:', error);
            return res.status(401).json({ error: 'Token inválido' });
        }
    } catch (error) {
        console.error('Erro no middleware de autenticação:', error);
        return res.status(500).json({ error: 'Erro interno do servidor' });
    }
};