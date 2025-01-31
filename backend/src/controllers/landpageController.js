const Landpage = require('../../models/Landpage');
const emailService = require('../services/emailService');
const spreadsheetService = require('../services/spreadsheetService');

class LandpageController {
    // Listar produtos disponíveis
    async getProducts(req, res) {
        try {
            const products = await Landpage.getProducts();
            res.json(products);
        } catch (error) {
            res.status(500).json({ error: 'Erro ao buscar produtos' });
        }
    }

    // Criar novo pedido
    async createOrder(req, res) {
        try {
            const { productId, digitalName } = req.body;
            const orderId = await Landpage.createOrder(req.user.id, productId, digitalName);
            res.status(201).json({
                orderId,
                message: 'Pedido criado com sucesso'
            });
        } catch (error) {
            res.status(400).json({ error: error.message });
        }
    }

    // Atualizar configurações
    async updateConfig(req, res) {
        try {
            await Landpage.updateConfig(req.user.id, req.params.id, req.body);
            res.json({ message: 'Configurações atualizadas com sucesso' });
        } catch (error) {
            res.status(400).json({ error: error.message });
        }
    }

    // Buscar landing page por nome digital
    async getLandpage(req, res) {
        try {
            const config = await Landpage.getByDigitalName(
                req.params.digitalName,
                req.params.type
            );

            if (!config) {
                return res.status(404).json({ error: 'Landing page não encontrada' });
            }

            res.json(config);
        } catch (error) {
            res.status(500).json({ error: 'Erro ao buscar landing page' });
        }
    }

    // Registrar novo lead
    async createLead(req, res) {
        try {
            const leadId = await Landpage.createLead(req.params.landpageId, req.body);

            // Enviar notificações
            await emailService.sendLeadNotification(req.body);
            await spreadsheetService.addLead(req.body);

            res.status(201).json({
                leadId,
                message: 'Lead registrado com sucesso'
            });
        } catch (error) {
            res.status(500).json({ error: 'Erro ao registrar lead' });
        }
    }
}

module.exports = new LandpageController();