-- Tabela para SEO
CREATE TABLE IF NOT EXISTS landing_page_seo (
    id INT AUTO_INCREMENT PRIMARY KEY,
    landing_page_id INT NOT NULL,
    title VARCHAR(255),
    description TEXT,
    keywords TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (landing_page_id) REFERENCES landing_pages(id) ON DELETE CASCADE,
    UNIQUE KEY unique_landing_page (landing_page_id)
);

-- Tabela para integrações
CREATE TABLE IF NOT EXISTS landing_page_integrations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    landing_page_id INT NOT NULL,
    webhook_url VARCHAR(255),
    whatsapp_link VARCHAR(255),
    email_link VARCHAR(255),
    email_integration JSON,
    crm_integration JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (landing_page_id) REFERENCES landing_pages(id) ON DELETE CASCADE,
    UNIQUE KEY unique_landing_page (landing_page_id)
);

-- Tabela para pixels de rastreamento
CREATE TABLE IF NOT EXISTS landing_page_pixels (
    id INT AUTO_INCREMENT PRIMARY KEY,
    landing_page_id INT NOT NULL,
    facebook_pixel VARCHAR(255),
    google_analytics VARCHAR(255),
    tiktok_pixel VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (landing_page_id) REFERENCES landing_pages(id) ON DELETE CASCADE,
    UNIQUE KEY unique_landing_page (landing_page_id)
);

-- Tabela para mídia
CREATE TABLE IF NOT EXISTS landing_page_media (
    id INT AUTO_INCREMENT PRIMARY KEY,
    landing_page_id INT NOT NULL,
    filename VARCHAR(255) NOT NULL,
    type ENUM('image', 'video', 'document') NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (landing_page_id) REFERENCES landing_pages(id) ON DELETE CASCADE
); 