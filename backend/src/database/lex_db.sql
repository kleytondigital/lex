-- Atualização da tabela landing_pages
ALTER TABLE landing_pages
ADD COLUMN IF NOT EXISTS whatsapp_number VARCHAR(20) DEFAULT NULL COMMENT 'Número do WhatsApp para contato',
ADD COLUMN IF NOT EXISTS whatsapp_link VARCHAR(255) DEFAULT NULL COMMENT 'Link formatado do WhatsApp',
ADD COLUMN IF NOT EXISTS referral_link VARCHAR(255) DEFAULT NULL COMMENT 'Link de indicação da Alexandria',
ADD COLUMN IF NOT EXISTS email VARCHAR(255) DEFAULT NULL COMMENT 'Email para contato',
ADD COLUMN IF NOT EXISTS template VARCHAR(50) DEFAULT NULL COMMENT 'ID do template selecionado',
ADD COLUMN IF NOT EXISTS content JSON DEFAULT NULL COMMENT 'Conteúdo da landing page (headline, subheadline, etc)',
ADD COLUMN IF NOT EXISTS seo JSON DEFAULT NULL COMMENT 'Configurações de SEO',
ADD COLUMN IF NOT EXISTS integrations JSON DEFAULT NULL COMMENT 'Configurações de integrações',
ADD COLUMN IF NOT EXISTS pixels JSON DEFAULT NULL COMMENT 'Configurações de pixels de rastreamento',
ADD COLUMN IF NOT EXISTS consultant_name VARCHAR(100) DEFAULT NULL COMMENT 'Nome do consultor',
ADD COLUMN IF NOT EXISTS consultant_role VARCHAR(100) DEFAULT 'Líder de expansão LEX' COMMENT 'Cargo do consultor',
ADD COLUMN IF NOT EXISTS consultant_message TEXT DEFAULT NULL COMMENT 'Mensagem de apresentação do consultor',
ADD COLUMN IF NOT EXISTS consultant_photo VARCHAR(255) DEFAULT NULL COMMENT 'URL da foto do consultor',
ADD COLUMN IF NOT EXISTS facebook_url VARCHAR(255) DEFAULT NULL COMMENT 'URL do perfil do Facebook',
ADD COLUMN IF NOT EXISTS instagram_url VARCHAR(255) DEFAULT NULL COMMENT 'URL do perfil do Instagram',
ADD COLUMN IF NOT EXISTS linkedin_url VARCHAR(255) DEFAULT NULL COMMENT 'URL do perfil do LinkedIn',
ADD COLUMN IF NOT EXISTS youtube_url VARCHAR(255) DEFAULT NULL COMMENT 'URL do canal do YouTube',
ADD COLUMN IF NOT EXISTS tiktok_url VARCHAR(255) DEFAULT NULL COMMENT 'URL do perfil do TikTok';

-- Comentários das colunas existentes
ALTER TABLE landing_pages
MODIFY COLUMN digital_name VARCHAR(255) NOT NULL COMMENT 'Nome digital único da landing page',
MODIFY COLUMN published BOOLEAN DEFAULT FALSE COMMENT 'Status de publicação da página',
MODIFY COLUMN objective ENUM('client', 'consultant') DEFAULT 'client' COMMENT 'Objetivo da landing page';

-- Índices para otimização
ALTER TABLE landing_pages
ADD INDEX IF NOT EXISTS idx_digital_name (digital_name),
ADD INDEX IF NOT EXISTS idx_published (published),
ADD INDEX IF NOT EXISTS idx_objective (objective); 