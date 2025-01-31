const connection = require('../database');
const nodemailer = require('nodemailer');

class EmailController {
    constructor() {
        this.transporter = null;
    }

    async initializeTransporter(userId) {
        try {
            const [settings] = await connection.query(
                'SELECT credentials FROM integration_settings WHERE user_id = ? AND type = ? AND is_active = TRUE', [userId, 'email']
            );

            if (!settings || settings.length === 0) {
                throw new Error('Configurações de email não encontradas');
            }

            const credentials = JSON.parse(settings[0].credentials);

            this.transporter = nodemailer.createTransport({
                host: credentials.host,
                port: credentials.port,
                secure: credentials.secure,
                auth: {
                    user: credentials.user,
                    pass: credentials.password
                }
            });
        } catch (error) {
            console.error('Erro ao inicializar transporter:', error);
            throw new Error('Erro ao configurar serviço de email');
        }
    }

    async send(req, res) {
        try {
            const { to, subject, text, html } = req.body;

            if (!this.transporter) {
                await this.initializeTransporter(req.userId);
            }

            const result = await this.transporter.sendMail({
                from: req.body.from || '"LEX Treinamentos" <noreply@lextreinamentos.com.br>',
                to,
                subject,
                text,
                html
            });

            res.json({ message: 'Email enviado com sucesso', messageId: result.messageId });
        } catch (error) {
            console.error('Erro ao enviar email:', error);
            res.status(500).json({ error: 'Erro ao enviar email' });
        }
    }

    async sendBulk(req, res) {
        try {
            const { emails } = req.body;

            if (!this.transporter) {
                await this.initializeTransporter(req.userId);
            }

            const results = await Promise.allSettled(
                emails.map(email => this.transporter.sendMail({
                    from: email.from || '"LEX Treinamentos" <noreply@lextreinamentos.com.br>',
                    to: email.to,
                    subject: email.subject,
                    text: email.text,
                    html: email.html
                }))
            );

            const summary = {
                total: emails.length,
                sent: results.filter(r => r.status === 'fulfilled').length,
                failed: results.filter(r => r.status === 'rejected').length
            };

            res.json(summary);
        } catch (error) {
            console.error('Erro ao enviar emails em massa:', error);
            res.status(500).json({ error: 'Erro ao enviar emails em massa' });
        }
    }

    async getTemplates(req, res) {
        try {
            const [templates] = await connection.query(
                'SELECT id, name, subject, content FROM email_templates WHERE user_id = ?', [req.userId]
            );
            res.json(templates);
        } catch (error) {
            console.error('Erro ao buscar templates:', error);
            res.status(500).json({ error: 'Erro ao buscar templates' });
        }
    }

    async createTemplate(req, res) {
        try {
            const { name, subject, content } = req.body;

            const [result] = await connection.query(
                'INSERT INTO email_templates (name, subject, content, user_id) VALUES (?, ?, ?, ?)', [name, subject, content, req.userId]
            );

            res.status(201).json({
                id: result.insertId,
                name,
                subject,
                content
            });
        } catch (error) {
            console.error('Erro ao criar template:', error);
            res.status(500).json({ error: 'Erro ao criar template' });
        }
    }

    async updateTemplate(req, res) {
        try {
            const { name, subject, content } = req.body;
            const { id } = req.params;

            await connection.query(
                'UPDATE email_templates SET name = ?, subject = ?, content = ? WHERE id = ? AND user_id = ?', [name, subject, content, id, req.userId]
            );

            res.json({ message: 'Template atualizado com sucesso' });
        } catch (error) {
            console.error('Erro ao atualizar template:', error);
            res.status(500).json({ error: 'Erro ao atualizar template' });
        }
    }

    async deleteTemplate(req, res) {
        try {
            const { id } = req.params;

            await connection.query(
                'DELETE FROM email_templates WHERE id = ? AND user_id = ?', [id, req.userId]
            );

            res.status(204).send();
        } catch (error) {
            console.error('Erro ao deletar template:', error);
            res.status(500).json({ error: 'Erro ao deletar template' });
        }
    }
}

module.exports = new EmailController();