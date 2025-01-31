// Middleware para verificar:
// - Se o usuário tem permissão para editar a landing page
// - Se o pagamento foi confirmado
// - Se o nome digital está disponível 

const Landpage = require('../../models/Landpage');

const landpageMiddleware = {
    async validateAccess(req, res, next) {
        try {
            const landpageId = req.params.id;
            const userId = req.user.id;

            const landpage = await Landpage.findById(landpageId);

            if (!landpage) {
                return res.status(404).json({ error: 'Landing page não encontrada' });
            }

            if (landpage.user_id !== userId) {
                return res.status(403).json({ error: 'Acesso negado' });
            }

            req.landpage = landpage;
            next();
        } catch (error) {
            res.status(500).json({ error: 'Erro ao validar acesso' });
        }
    },

    async validatePayment(req, res, next) {
        try {
            const order = await Landpage.getOrderByUserId(req.user.id);

            if (!order || order.status !== 'paid') {
                return res.status(403).json({
                    error: 'Você precisa ter um pedido pago para acessar esta funcionalidade'
                });
            }

            next();
        } catch (error) {
            res.status(500).json({ error: 'Erro ao validar pagamento' });
        }
    },

    async validateDigitalName(req, res, next) {
        try {
            const { digitalName } = req.body;

            if (!digitalName) {
                return res.status(400).json({ error: 'Nome digital é obrigatório' });
            }

            const exists = await Landpage.checkDigitalNameExists(digitalName);

            if (exists) {
                return res.status(400).json({ error: 'Nome digital já está em uso' });
            }

            next();
        } catch (error) {
            res.status(500).json({ error: 'Erro ao validar nome digital' });
        }
    }
};

module.exports = landpageMiddleware;