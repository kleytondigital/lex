-- Tabela de produtos
CREATE TABLE products (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL,
    type ENUM('landpage', 'other') NOT NULL,
    status ENUM('active', 'inactive') DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de pedidos
CREATE TABLE orders (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    product_id INT NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    status ENUM('pending', 'paid', 'cancelled', 'refunded') DEFAULT 'pending',
    payment_method ENUM('pix', 'credit_card') NOT NULL,
    payment_id VARCHAR(100),
    digital_name VARCHAR(50) UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- Tabela de configurações das landing pages
CREATE TABLE landpage_configs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    type ENUM('client', 'consultant') NOT NULL,
    headline VARCHAR(255),
    consultant_photo VARCHAR(255),
    contact_email VARCHAR(100),
    contact_whatsapp VARCHAR(20),
    referral_link VARCHAR(255),
    show_video BOOLEAN DEFAULT true,
    show_company_images BOOLEAN DEFAULT true,
    show_social_proof BOOLEAN DEFAULT true,
    status ENUM('draft', 'published') DEFAULT 'draft',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Tabela de leads
CREATE TABLE leads (
    id INT PRIMARY KEY AUTO_INCREMENT,
    landpage_id INT NOT NULL,
    consultant_id INT NOT NULL,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL,
    phone VARCHAR(20) NOT NULL,
    type ENUM('client', 'consultant') NOT NULL,
    status ENUM('new', 'contacted', 'converted', 'lost') DEFAULT 'new',
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (consultant_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (landpage_id) REFERENCES landpage_configs(id) ON DELETE CASCADE
);

-- Índices
CREATE INDEX idx_orders_digital_name ON orders(digital_name);
CREATE INDEX idx_leads_consultant ON leads(consultant_id);
CREATE INDEX idx_leads_type ON leads(type);
CREATE INDEX idx_leads_status ON leads(status);
CREATE INDEX idx_landpage_user ON landpage_configs(user_id);
CREATE INDEX idx_landpage_type ON landpage_configs(type); 