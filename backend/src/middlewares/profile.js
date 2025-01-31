const profileMiddleware = {
    async checkProfileComplete(req, res, next) {
        if (!req.user.profile_complete) {
            return res.status(403).json({
                error: 'Você precisa completar seu perfil antes de acessar esta funcionalidade',
                code: 'PROFILE_INCOMPLETE'
            });
        }
        next();
    }
};

module.exports = profileMiddleware;