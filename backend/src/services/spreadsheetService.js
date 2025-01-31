// Serviço para salvar leads na planilha Google 
const { google } = require('googleapis');
const connection = require('../database');

class SpreadsheetService {
    async getCredentials(userId) {
        const [rows] = await connection.query(
            'SELECT credentials, settings FROM integration_settings WHERE user_id = ? AND type = ? AND is_active = TRUE', [userId, 'google_sheets']
        );

        if (!rows || rows.length === 0) {
            return null;
        }

        return {
            credentials: JSON.parse(rows[0].credentials),
            settings: JSON.parse(rows[0].settings)
        };
    }

    async addLead(leadData, userId) {
        try {
            const integrationSettings = await this.getCredentials(userId);

            // Se não houver configuração de planilha, apenas retorna sem erro
            if (!integrationSettings) {
                return;
            }

            const { credentials, settings } = integrationSettings;

            const auth = new google.auth.GoogleAuth({
                credentials,
                scopes: ['https://www.googleapis.com/auth/spreadsheets']
            });

            const sheets = google.sheets({ version: 'v4', auth });

            // Formata os dados do lead conforme configurado pelo usuário
            const values = [this.formatLeadData(leadData, settings.columns)];

            await sheets.spreadsheets.values.append({
                spreadsheetId: settings.spreadsheetId,
                range: settings.sheetName || 'Leads',
                valueInputOption: 'USER_ENTERED',
                resource: { values },
            });

        } catch (error) {
            console.error('Erro ao adicionar lead na planilha:', error);
            // Não lança erro para não interromper o fluxo principal
        }
    }

    formatLeadData(leadData, columns) {
        if (!columns) {
            // Formato padrão se não houver configuração específica
            return [
                leadData.name,
                leadData.email,
                leadData.phone,
                leadData.source,
                new Date().toISOString()
            ];
        }

        // Formata os dados conforme configuração do usuário
        return columns.map(column => leadData[column] || '');
    }

    async saveCredentials(userId, credentials, settings) {
        try {
            await connection.query(
                `INSERT INTO integration_settings (user_id, type, credentials, settings, is_active) 
                VALUES (?, ?, ?, ?, TRUE)
                ON DUPLICATE KEY UPDATE 
                credentials = VALUES(credentials),
                settings = VALUES(settings),
                is_active = TRUE`, [userId, 'google_sheets', JSON.stringify(credentials), JSON.stringify(settings)]
            );
            return true;
        } catch (error) {
            console.error('Erro ao salvar credenciais:', error);
            throw new Error('Erro ao salvar configurações da planilha');
        }
    }

    async disconnectSpreadsheet(userId) {
        try {
            await connection.query(
                'UPDATE integration_settings SET is_active = FALSE WHERE user_id = ? AND type = ?', [userId, 'google_sheets']
            );
            return true;
        } catch (error) {
            console.error('Erro ao desconectar planilha:', error);
            throw new Error('Erro ao desconectar planilha');
        }
    }

    async syncData(userId, data) {
        try {
            const integrationSettings = await this.getCredentials(userId);

            if (!integrationSettings) {
                throw new Error('Planilha não configurada');
            }

            const { credentials, settings } = integrationSettings;

            const auth = new google.auth.GoogleAuth({
                credentials,
                scopes: ['https://www.googleapis.com/auth/spreadsheets']
            });

            const sheets = google.sheets({ version: 'v4', auth });

            // Formata os dados conforme configuração
            const values = data.map(row => this.formatLeadData(row, settings.columns));

            await sheets.spreadsheets.values.append({
                spreadsheetId: settings.spreadsheetId,
                range: settings.sheetName || 'Leads',
                valueInputOption: 'USER_ENTERED',
                resource: { values },
            });

            return true;
        } catch (error) {
            console.error('Erro ao sincronizar dados:', error);
            throw new Error('Erro ao sincronizar dados com a planilha');
        }
    }
}

module.exports = new SpreadsheetService();