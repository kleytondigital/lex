const adminMiddleware = (req, res, next) => {
    if (req.userRole === 'admin') {
        next();
    } else {
        res.status(403).json({ error: 'Acesso negado' });
    }
};

module.exports = adminMiddleware;