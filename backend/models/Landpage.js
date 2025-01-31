const mysql = require('mysql2/promise');
const config = require('../src/config/config');

const pool = mysql.createPool({
    host: config.database.host,
    user: config.database.user,
    password: config.database.password,
    database: config.database.database,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

class Landpage {
    // Buscar produtos disponíveis
    static async getProducts() {
        const [rows] = await pool.query(
            'SELECT * FROM products WHERE type = "landpage" AND status = "active"'
        );
        return rows;
    }

    // Criar novo pedido
    static async createOrder(userId, productId, digitalName) {
        const conn = await pool.getConnection();

        try {
            await conn.beginTransaction();

            // Buscar preço do produto
            const [products] = await conn.query(
                'SELECT price FROM products WHERE id = ? AND status = "active"', [productId]
            );

            if (!products.length) {
                throw new Error('Produto não encontrado');
            }

            // Verificar se já existe pedido ativo para este usuário
            const [existingOrders] = await conn.query(
                'SELECT id FROM orders WHERE user_id = ? AND status IN ("pending", "paid")', [userId]
            );

            if (existingOrders.length > 0) {
                throw new Error('Usuário já possui um pedido ativo');
            }

            // Verificar se nome digital já está em uso
            const [existingNames] = await conn.query(
                'SELECT id FROM orders WHERE digital_name = ?', [digitalName]
            );

            if (existingNames.length > 0) {
                throw new Error('Nome digital já está em uso');
            }

            // Criar pedido
            const [result] = await conn.query(
                `INSERT INTO orders (
                    user_id, product_id, amount, digital_name, status
                ) VALUES (?, ?, ?, ?, 'pending')`, [userId, productId, products[0].price, digitalName]
            );

            // Criar configurações iniciais para ambas landing pages
            await conn.query(
                `INSERT INTO landpage_configs (
                    user_id, order_id, type, status
                ) VALUES 
                (?, ?, 'client', 'draft'),
                (?, ?, 'consultant', 'draft')`, [userId, result.insertId, userId, result.insertId]
            );

            await conn.commit();
            return result.insertId;

        } catch (error) {
            await conn.rollback();
            throw error;
        } finally {
            conn.release();
        }
    }

    // Atualizar configurações da landing page
    static async updateConfig(id, configData) {
        const conn = await pool.getConnection();
        try {
            await conn.beginTransaction();

            await conn.query(
                `UPDATE landpage_configs SET
                    headline = ?,
                    contact_email = ?,
                    contact_whatsapp = ?,
                    referral_link = ?,
                    show_video = ?,
                    show_company_images = ?,
                    show_social_proof = ?,
                    status = ?
                WHERE id = ?`, [
                    configData.headline,
                    configData.contactEmail,
                    configData.contactWhatsapp,
                    configData.referralLink,
                    configData.showVideo,
                    configData.showCompanyImages,
                    configData.showSocialProof,
                    configData.status,
                    id
                ]
            );

            await conn.commit();
            return true;
        } catch (error) {
            await conn.rollback();
            throw error;
        } finally {
            conn.release();
        }
    }

    static async updateConsultantPhoto(userId, photoUrl) {
        const [result] = await pool.query(
            'UPDATE landpage_configs SET consultant_photo = ? WHERE user_id = ?', [photoUrl, userId]
        );
        return result.affectedRows > 0;
    }

    // Buscar configurações da landing page por nome digital
    static async getByDigitalName(digitalName, type) {
        const [rows] = await pool.query(
            `SELECT lc.* 
            FROM landpage_configs lc
            JOIN orders o ON o.id = lc.order_id
            WHERE o.digital_name = ? 
            AND o.status = 'paid'
            AND lc.type = ?
            AND lc.status = 'published'`, [digitalName, type]
        );

        return rows[0] || null;
    }

    // Registrar novo lead
    static async createLead(leadData) {
        const conn = await pool.getConnection();
        try {
            await conn.beginTransaction();

            const [result] = await conn.query(
                `INSERT INTO leads (
                    landpage_id, consultant_id, name, email, 
                    phone, type, status
                ) VALUES (?, ?, ?, ?, ?, ?, 'new')`, [
                    leadData.landpageId,
                    leadData.consultantId,
                    leadData.name,
                    leadData.email,
                    leadData.phone,
                    leadData.type
                ]
            );

            await conn.commit();
            return result.insertId;
        } catch (error) {
            await conn.rollback();
            throw error;
        } finally {
            conn.release();
        }
    }

    static async getConfigsByUserId(userId) {
        const [rows] = await pool.query(
            'SELECT * FROM landpage_configs WHERE user_id = ?', [userId]
        );
        return rows;
    }

    static async getConsultantByDigitalName(digitalName) {
        const [rows] = await pool.query(
            `SELECT u.*, lc.id as landpage_id 
            FROM users u 
            JOIN landpage_configs lc ON u.id = lc.user_id 
            WHERE u.digital_name = ? AND lc.status = 'published'`, [digitalName]
        );
        return rows[0];
    }

    static async getLeadsByConsultantId(consultantId) {
        const [rows] = await pool.query(
            'SELECT * FROM leads WHERE consultant_id = ? ORDER BY created_at DESC', [consultantId]
        );
        return rows;
    }

    static async checkDigitalNameExists(digitalName) {
        const [rows] = await pool.query(
            'SELECT COUNT(*) as count FROM users WHERE digital_name = ?', [digitalName]
        );
        return rows[0].count > 0;
    }

    static async getOrderByUserId(userId) {
        const [rows] = await pool.query(
            'SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC LIMIT 1', [userId]
        );
        return rows[0];
    }
}

module.exports = Landpage;