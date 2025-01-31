const connection = require('../database');
const path = require('path');
const fs = require('fs');
const fsPromises = require('fs').promises;
const mysql = require('mysql2/promise');
const dbConfig = require('../config/db');

class LandingPageController {
    async index(req, res) {
        try {
            const [landingPages] = await connection.query(
                'SELECT * FROM landing_pages WHERE user_id = ? ORDER BY created_at DESC', [req.userId]
            );
            res.json(landingPages);
        } catch (error) {
            console.error('Erro ao listar landing pages:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async store(req, res) {
        try {
            const { digitalName, objective } = req.body;

            // Verifica se já existe uma página com este nome digital
            const [existing] = await connection.query(
                'SELECT id FROM landing_pages WHERE digital_name = ?', [digitalName]
            );

            if (existing.length > 0) {
                return res.status(400).json({ error: 'Já existe uma página com este nome' });
            }

            const [result] = await connection.query(
                'INSERT INTO landing_pages (digital_name, objective, user_id) VALUES (?, ?, ?)', [digitalName, objective, req.userId]
            );

            res.status(201).json({
                id: result.insertId,
                digitalName,
                objective
            });
        } catch (error) {
            console.error('Erro ao criar landing page:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async show(req, res) {
        try {
            const [landingPage] = await connection.query(
                'SELECT * FROM landing_pages WHERE id = ? AND user_id = ?', [req.params.id, req.userId]
            );

            if (landingPage.length === 0) {
                return res.status(404).json({ error: 'Landing page não encontrada' });
            }

            res.json(landingPage[0]);
        } catch (error) {
            console.error('Erro ao buscar landing page:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async update(req, res) {
        try {
            const { template, content, published } = req.body;
            const { id } = req.params;

            const [landingPage] = await connection.query(
                'SELECT * FROM landing_pages WHERE id = ? AND user_id = ?', [id, req.userId]
            );

            if (landingPage.length === 0) {
                return res.status(404).json({ error: 'Landing page não encontrada' });
            }

            await connection.query(
                'UPDATE landing_pages SET template = ?, content = ?, published = ? WHERE id = ?', [template, JSON.stringify(content), published, id]
            );

            res.json({ message: 'Landing page atualizada com sucesso' });
        } catch (error) {
            console.error('Erro ao atualizar landing page:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async destroy(req, res) {
        try {
            const [result] = await connection.query(
                'DELETE FROM landing_pages WHERE id = ? AND user_id = ?', [req.params.id, req.userId]
            );

            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'Landing page não encontrada' });
            }

            res.status(204).send();
        } catch (error) {
            console.error('Erro ao deletar landing page:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async uploadMedia(req, res) {
        try {
            if (!req.file) {
                return res.status(400).json({ error: 'Nenhum arquivo enviado' });
            }

            const mediaUrl = `/uploads/landpage/${req.file.filename}`;

            await connection.query(
                'INSERT INTO landing_page_media (landing_page_id, url) VALUES (?, ?)', [req.params.id, mediaUrl]
            );

            res.json({ url: mediaUrl });
        } catch (error) {
            console.error('Erro ao fazer upload de mídia:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async deleteMedia(req, res) {
        try {
            const [media] = await connection.query(
                'SELECT url FROM landing_page_media WHERE id = ? AND landing_page_id = ?', [req.params.mediaId, req.params.id]
            );

            if (media.length === 0) {
                return res.status(404).json({ error: 'Mídia não encontrada' });
            }

            // Remove o arquivo
            const filePath = path.join(__dirname, '../../public', media[0].url);
            await fsPromises.unlink(filePath);

            await connection.query(
                'DELETE FROM landing_page_media WHERE id = ?', [req.params.mediaId]
            );

            res.status(204).send();
        } catch (error) {
            console.error('Erro ao deletar mídia:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async publish(req, res) {
        try {
            await connection.query(
                'UPDATE landing_pages SET published = TRUE WHERE id = ? AND user_id = ?', [req.params.id, req.userId]
            );
            res.json({ message: 'Landing page publicada com sucesso' });
        } catch (error) {
            console.error('Erro ao publicar landing page:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async unpublish(req, res) {
        try {
            await connection.query(
                'UPDATE landing_pages SET published = FALSE WHERE id = ? AND user_id = ?', [req.params.id, req.userId]
            );
            res.json({ message: 'Landing page despublicada com sucesso' });
        } catch (error) {
            console.error('Erro ao despublicar landing page:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async duplicate(req, res) {
        try {
            const [original] = await connection.query(
                'SELECT * FROM landing_pages WHERE id = ? AND user_id = ?', [req.params.id, req.userId]
            );

            if (original.length === 0) {
                return res.status(404).json({ error: 'Landing page não encontrada' });
            }

            const landingPage = original[0];
            const newDigitalName = `${landingPage.digital_name}-copy`;

            const [result] = await connection.query(
                `INSERT INTO landing_pages 
                (digital_name, objective, template, content, user_id) 
                VALUES (?, ?, ?, ?, ?)`, [newDigitalName, landingPage.objective, landingPage.template, landingPage.content, req.userId]
            );

            res.status(201).json({
                id: result.insertId,
                digitalName: newDigitalName,
                message: 'Landing page duplicada com sucesso'
            });
        } catch (error) {
            console.error('Erro ao duplicar landing page:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async getStats(req, res) {
        try {
            const [stats] = await connection.query(
                `SELECT 
                    COUNT(*) as total_leads,
                    COUNT(CASE WHEN l.status = 'converted' THEN 1 END) as converted_leads,
                    DATE_FORMAT(l.created_at, '%Y-%m-%d') as date
                FROM leads l
                WHERE l.landing_page_id = ?
                GROUP BY DATE_FORMAT(l.created_at, '%Y-%m-%d')
                ORDER BY date DESC
                LIMIT 30`, [req.params.id]
            );
            res.json(stats);
        } catch (error) {
            console.error('Erro ao buscar estatísticas:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async getConfig(req, res) {
        const { id } = req.params;
        const userId = req.userId;

        try {
            const connection = await mysql.createConnection(dbConfig);

            const [rows] = await connection.query(
                `SELECT 
                    lp.id,
                    lp.digital_name,
                    lp.published,
                    lp.objective,
                    lp.whatsapp_number,
                    lp.whatsapp_link,
                    lp.referral_link,
                    lp.email,
                    lp.template,
                    lp.content,
                    lp.seo,
                    lp.integrations,
                    lp.pixels,
                    lp.consultant_name,
                    lp.consultant_role,
                    lp.consultant_message,
                    lp.consultant_photo,
                    lp.facebook_url,
                    lp.instagram_url,
                    lp.linkedin_url,
                    lp.youtube_url,
                    lp.tiktok_url
                FROM landing_pages lp
                WHERE lp.id = ? AND lp.user_id = ?`, [id, userId]
            );

            await connection.end();

            if (!rows.length) {
                return res.status(404).json({ error: 'Landing page não encontrada' });
            }

            const landingPage = rows[0];

            // Parse JSON fields
            landingPage.content = landingPage.content ? JSON.parse(landingPage.content) : null;
            landingPage.seo = landingPage.seo ? JSON.parse(landingPage.seo) : null;
            landingPage.integrations = landingPage.integrations ? JSON.parse(landingPage.integrations) : null;
            landingPage.pixels = landingPage.pixels ? JSON.parse(landingPage.pixels) : null;

            // Set default consultant message if empty
            if (!landingPage.consultant_message) {
                landingPage.consultant_message = "Olá! Sou especialista em energia solar e estou aqui para ajudar você a economizar na conta de luz. Vamos conversar?";
            }

            return res.json(landingPage);
        } catch (error) {
            console.error('Erro ao buscar configurações:', error);
            return res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async updateConfig(req, res) {
        const { id } = req.params;
        const userId = req.userId;
        const {
            digital_name,
            published,
            objective,
            whatsapp_number,
            whatsapp_link,
            referral_link,
            email,
            template,
            content,
            seo,
            integrations,
            pixels,
            consultant_name,
            consultant_role,
            consultant_message,
            consultant_photo,
            facebook_url,
            instagram_url,
            linkedin_url,
            youtube_url,
            tiktok_url
        } = req.body;

        try {
            const connection = await mysql.createConnection(dbConfig);

            // Verificar se o nome digital já existe (exceto para a própria landing page)
            if (digital_name) {
                const [existingPages] = await connection.query(
                    'SELECT id FROM landing_pages WHERE digital_name = ? AND id != ? AND user_id = ?', [digital_name, id, userId]
                );

                if (existingPages.length > 0) {
                    await connection.end();
                    return res.status(400).json({ error: 'Nome digital já está em uso' });
                }
            }

            // Preparar os dados para atualização
            const updateData = {
                digital_name,
                published,
                objective,
                whatsapp_number,
                whatsapp_link,
                referral_link,
                email,
                template,
                content: content ? JSON.stringify(content) : null,
                seo: seo ? JSON.stringify(seo) : null,
                integrations: integrations ? JSON.stringify(integrations) : null,
                pixels: pixels ? JSON.stringify(pixels) : null,
                consultant_name,
                consultant_role,
                consultant_message,
                consultant_photo,
                facebook_url,
                instagram_url,
                linkedin_url,
                youtube_url,
                tiktok_url
            };

            // Remover campos undefined/null
            Object.keys(updateData).forEach(key => {
                if (updateData[key] === undefined) {
                    delete updateData[key];
                }
            });

            // Atualizar a landing page
            await connection.query(
                'UPDATE landing_pages SET ? WHERE id = ? AND user_id = ?', [updateData, id, userId]
            );

            await connection.end();

            return res.json({ message: 'Configurações atualizadas com sucesso' });
        } catch (error) {
            console.error('Erro ao atualizar configurações:', error);
            return res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    async getByDigitalName(req, res) {
        const { digitalName } = req.params;
        // console.log('Parâmetros da requisição:', req.params);
        // console.log('Buscando landing page com digital_name:', digitalName);

        try {
            const connection = await mysql.createConnection(dbConfig);

            // Primeiro vamos verificar se existe a landing page sem a condição de published
            const [checkExists] = await connection.query(
                `SELECT id, digital_name, published 
                 FROM landing_pages 
                 WHERE digital_name = ?`, [digitalName]
            );

            // console.log('Verificação inicial:', {
            //     exists: checkExists.length > 0,
            //     record: checkExists[0] || null
            // });

            // console.log('Executando query principal...');
            const [rows] = await connection.query(
                `SELECT 
                    lp.id,
                    lp.digital_name,
                    lp.published,
                    lp.objective,
                    lp.whatsapp_number,
                    lp.whatsapp_link,
                    lp.referral_link,
                    lp.email,
                    lp.template,
                    lp.content,
                    lp.seo,
                    lp.integrations,
                    lp.pixels,
                    lp.consultant_name,
                    lp.consultant_role,
                    lp.consultant_message,
                    lp.consultant_photo,
                    lp.facebook_url,
                    lp.instagram_url,
                    lp.linkedin_url,
                    lp.youtube_url,
                    lp.tiktok_url
                FROM landing_pages lp
                WHERE lp.digital_name = ? 
                AND lp.published = true`, [digitalName]
            );
            // console.log('Resultado da query principal:', {
            //     found: rows.length > 0,
            //     record: rows[0] || null
            // });

            await connection.end();

            if (!rows.length) {
                return res.status(404).json({
                    error: 'Landing page não encontrada',
                    details: checkExists.length > 0 ? 'Landing page existe mas não está publicada' : 'Landing page não existe'
                });
            }

            const landingPage = rows[0];

            // Parse JSON fields
            landingPage.content = landingPage.content ? JSON.parse(landingPage.content) : {};
            landingPage.seo = landingPage.seo ? JSON.parse(landingPage.seo) : {};
            landingPage.integrations = landingPage.integrations ? JSON.parse(landingPage.integrations) : {};
            landingPage.pixels = landingPage.pixels ? JSON.parse(landingPage.pixels) : {};

            // Set default consultant message if empty
            if (!landingPage.consultant_message) {
                landingPage.consultant_message = "Olá! Sou especialista em energia solar e estou aqui para ajudar você a economizar na conta de luz. Vamos conversar?";
            }

            // Estruturar os dados para o template
            const templateData = {
                content: {
                    ...landingPage.content,
                    consultant: {
                        name: landingPage.consultant_name,
                        role: landingPage.consultant_role,
                        message: landingPage.consultant_message
                    },
                    videoUrl: landingPage.content.videoUrl
                },
                seo: landingPage.seo,
                integrations: {
                    ...landingPage.integrations,
                    whatsappNumber: landingPage.whatsapp_number,
                    whatsappLink: landingPage.whatsapp_link,
                    referralLink: landingPage.referral_link
                },
                consultant_photo: landingPage.consultant_photo,
                facebook_url: landingPage.facebook_url,
                instagram_url: landingPage.instagram_url,
                linkedin_url: landingPage.linkedin_url,
                youtube_url: landingPage.youtube_url,
                tiktok_url: landingPage.tiktok_url
            };

            res.json(templateData);
        } catch (error) {
            console.error('Erro ao buscar landing page por nome digital:', error);
            res.status(500).json({ error: 'Erro interno do servidor' });
        }
    }

    // Add new method for photo upload
    async uploadPhoto(req, res) {
        if (!req.file) {
            return res.status(400).json({ error: 'Nenhuma foto foi enviada' });
        }

        try {
            // Garantir que o diretório de uploads existe
            const uploadDir = path.join(process.cwd(), 'public', 'uploads');
            if (!fs.existsSync(uploadDir)) {
                await fsPromises.mkdir(uploadDir, { recursive: true });
            }

            // Gerar nome único para o arquivo
            const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
            const filename = `${req.userId}-${uniqueSuffix}${path.extname(req.file.originalname)}`;
            const targetPath = path.join(uploadDir, filename);

            // Copiar o arquivo para o diretório de destino
            await fsPromises.copyFile(req.file.path, targetPath);

            // Remover o arquivo temporário
            await fsPromises.unlink(req.file.path);

            // Retornar apenas o nome do arquivo
            return res.status(200).json({
                filename,
                message: 'Foto enviada com sucesso'
            });
        } catch (error) {
            // Em caso de erro, tentar remover o arquivo temporário se ele existir
            if (req.file && req.file.path && fs.existsSync(req.file.path)) {
                try {
                    await fsPromises.unlink(req.file.path);
                } catch (unlinkError) {
                    console.error('Erro ao remover arquivo temporário:', unlinkError);
                }
            }

            console.error('Erro ao fazer upload da foto:', error);
            return res.status(500).json({ error: 'Erro ao fazer upload da foto' });
        }
    }
}

module.exports = new LandingPageController();