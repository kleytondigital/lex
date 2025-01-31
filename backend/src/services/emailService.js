// Serviço para envio de notificações por email quando receber leads 
const nodemailer = require('nodemailer');
const config = require('../config/config');

class EmailService {
    constructor() {
        this.transporter = nodemailer.createTransport({
            host: config.email.host,
            port: config.email.port,
            secure: false,
            auth: {
                user: config.email.user,
                pass: config.email.pass
            }
        });
    }

    async sendLeadNotification(lead, consultantEmail) {
        const mailOptions = {
            from: config.email.from,
            to: consultantEmail,
            subject: `Novo Lead - ${lead.type === 'client' ? 'Cliente' : 'Consultor'}`,
            html: `
                <h2>Novo Lead Recebido!</h2>
                <p><strong>Nome:</strong> ${lead.name}</p>
                <p><strong>Email:</strong> ${lead.email}</p>
                <p><strong>Telefone:</strong> ${lead.phone}</p>
                <p><strong>Tipo:</strong> ${lead.type === 'client' ? 'Cliente' : 'Consultor'}</p>
                <p><strong>Data:</strong> ${new Date().toLocaleString('pt-BR')}</p>
            `
        };

        try {
            await this.transporter.sendMail(mailOptions);
            return true;
        } catch (error) {
            console.error('Erro ao enviar email:', error);
            return false;
        }
    }
}

module.exports = new EmailService();