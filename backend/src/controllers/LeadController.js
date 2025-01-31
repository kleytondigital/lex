const connection = require('../database');

module.exports = {
    async index(req, res) {
        try {
            const [leads] = await connection.query(
                'SELECT * FROM leads WHERE user_id = ? ORDER BY created_at DESC', [req.userId]
            );
            res.json(leads);
        } catch (error) {
            console.error('Erro ao listar leads:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    },

    async show(req, res) {
        try {
            const [lead] = await connection.query(
                'SELECT * FROM leads WHERE id = ? AND user_id = ?', [req.params.id, req.userId]
            );

            if (!lead.length) {
                return res.status(404).json({ error: 'Lead não encontrado' });
            }

            res.json(lead[0]);
        } catch (error) {
            console.error('Erro ao buscar lead:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    },

    async store(req, res) {
        try {
            const { name, email, phone, source, landingPageId } = req.body;

            const [result] = await connection.query(
                'INSERT INTO leads (name, email, phone, source, landing_page_id, user_id) VALUES (?, ?, ?, ?, ?, ?)', [name, email, phone, source, landingPageId, req.userId]
            );

            res.status(201).json({
                id: result.insertId,
                name,
                email,
                phone,
                source,
                landingPageId
            });
        } catch (error) {
            console.error('Erro ao criar lead:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    },

    async update(req, res) {
        try {
            const { name, email, phone, status } = req.body;

            await connection.query(
                'UPDATE leads SET name = ?, email = ?, phone = ?, status = ? WHERE id = ? AND user_id = ?', [name, email, phone, status, req.params.id, req.userId]
            );

            res.json({ message: 'Lead atualizado com sucesso' });
        } catch (error) {
            console.error('Erro ao atualizar lead:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    },

    async destroy(req, res) {
        try {
            await connection.query(
                'DELETE FROM leads WHERE id = ? AND user_id = ?', [req.params.id, req.userId]
            );

            res.status(204).send();
        } catch (error) {
            console.error('Erro ao deletar lead:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    },

    // Métodos de exportação
    async exportToExcel(req, res) {
        // Implementar exportação para Excel
        res.status(501).json({ message: 'Funcionalidade em desenvolvimento' });
    },

    async exportToCSV(req, res) {
        // Implementar exportação para CSV
        res.status(501).json({ message: 'Funcionalidade em desenvolvimento' });
    },

    // Métodos de busca e filtro
    async search(req, res) {
        try {
            const { term } = req.query;
            const [leads] = await connection.query(
                `SELECT * FROM leads 
                WHERE user_id = ? 
                AND (name LIKE ? OR email LIKE ? OR phone LIKE ?)
                ORDER BY created_at DESC`, [req.userId, `%${term}%`, `%${term}%`, `%${term}%`]
            );
            res.json(leads);
        } catch (error) {
            console.error('Erro na busca de leads:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    },

    async filter(req, res) {
        try {
            const { status, source, startDate, endDate } = req.query;
            let query = 'SELECT * FROM leads WHERE user_id = ?';
            const params = [req.userId];

            if (status) {
                query += ' AND status = ?';
                params.push(status);
            }

            if (source) {
                query += ' AND source = ?';
                params.push(source);
            }

            if (startDate) {
                query += ' AND created_at >= ?';
                params.push(startDate);
            }

            if (endDate) {
                query += ' AND created_at <= ?';
                params.push(endDate);
            }

            query += ' ORDER BY created_at DESC';

            const [leads] = await connection.query(query, params);
            res.json(leads);
        } catch (error) {
            console.error('Erro ao filtrar leads:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    },

    // Métodos de estatísticas
    async getOverviewStats(req, res) {
        try {
            const [stats] = await connection.query(
                `SELECT 
                    COUNT(*) as total,
                    COUNT(CASE WHEN status = 'new' THEN 1 END) as new_leads,
                    COUNT(CASE WHEN status = 'contacted' THEN 1 END) as contacted,
                    COUNT(CASE WHEN status = 'converted' THEN 1 END) as converted
                FROM leads 
                WHERE user_id = ?`, [req.userId]
            );
            res.json(stats[0]);
        } catch (error) {
            console.error('Erro ao buscar estatísticas:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    },

    async getConversionStats(req, res) {
        // Implementar estatísticas de conversão
        res.status(501).json({ message: 'Funcionalidade em desenvolvimento' });
    },

    async getSourceStats(req, res) {
        try {
            const [stats] = await connection.query(
                `SELECT source, COUNT(*) as count
                FROM leads 
                WHERE user_id = ?
                GROUP BY source`, [req.userId]
            );
            res.json(stats);
        } catch (error) {
            console.error('Erro ao buscar estatísticas por fonte:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }
};