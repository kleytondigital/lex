const spreadsheetService = require('../services/spreadsheetService');

module.exports = {
    async connect(req, res) {
        try {
            const { credentials, settings } = req.body;
            await spreadsheetService.saveCredentials(req.userId, credentials, settings);
            res.json({ message: 'Planilha conectada com sucesso' });
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    },

    async sync(req, res) {
        try {
            const { data } = req.body;
            await spreadsheetService.syncData(req.userId, data);
            res.json({ message: 'Dados sincronizados com sucesso' });
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    },

    async getStatus(req, res) {
        try {
            const credentials = await spreadsheetService.getCredentials(req.userId);
            res.json({
                connected: !!credentials,
                settings: credentials && credentials.settings ? credentials.settings : null
            });
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    },

    async disconnect(req, res) {
        try {
            await spreadsheetService.disconnectSpreadsheet(req.userId);
            res.json({ message: 'Planilha desconectada com sucesso' });
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    }
};