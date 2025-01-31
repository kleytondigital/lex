-- Criação do banco de dados
CREATE DATABASE IF NOT EXISTS lex_db;
USE lex_db;

-- Tabela de usuários
CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('user', 'admin') DEFAULT 'user',
    avatar VARCHAR(255),
    status ENUM('active', 'inactive') DEFAULT 'active',
    email_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Tabela de cursos
CREATE TABLE IF NOT EXISTS courses (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    instructor VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,
    duration VARCHAR(50),
    price DECIMAL(10,2) NOT NULL,
    thumbnail VARCHAR(255),
    status ENUM('draft', 'published') DEFAULT 'draft',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Tabela de lições
CREATE TABLE lessons (
    id INT PRIMARY KEY AUTO_INCREMENT,
    course_id INT NOT NULL,
    title VARCHAR(100) NOT NULL,
    description TEXT,
    video_url VARCHAR(255),
    duration VARCHAR(50),
    order_index INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
);

-- Tabela de progresso do usuário
CREATE TABLE IF NOT EXISTS user_progress (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    course_id INT NOT NULL,
    progress INT DEFAULT 0,
    completed BOOLEAN DEFAULT FALSE,
    last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_course (user_id, course_id)
);

-- Tabela de configurações do sistema
CREATE TABLE settings (
    id INT PRIMARY KEY AUTO_INCREMENT,
    allow_registration BOOLEAN DEFAULT TRUE,
    require_email_verification BOOLEAN DEFAULT TRUE,
    max_file_size INT DEFAULT 10,
    supported_file_types JSON,
    smtp_settings JSON,
    payment_gateway JSON,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Inserir usuários iniciais (senha: 123456)
INSERT INTO users (name, email, password, role) VALUES
('Admin', 'admin@lex.com', '$2b$10$YourHashedPasswordHere', 'admin'),
('User', 'user@lex.com', '$2b$10$YourHashedPasswordHere', 'user');

-- Inserir configurações iniciais
INSERT INTO settings (
    allow_registration,
    require_email_verification,
    max_file_size,
    supported_file_types,
    smtp_settings,
    payment_gateway
) VALUES (
    TRUE,
    TRUE,
    10,
    '["pdf", "doc", "docx", "mp4"]',
    '{"host": "", "port": "", "user": "", "password": "", "fromEmail": ""}',
    '{"provider": "stripe", "apiKey": "", "secretKey": ""}'
);

-- Inserir alguns dados de teste
INSERT INTO user_progress (user_id, course_id, progress, completed) VALUES
(1, 1, 75, false),
(1, 2, 100, true),
(1, 3, 30, false);

-- Tabela de cursos
ALTER TABLE courses ADD COLUMN type ENUM('free', 'premium') NOT NULL DEFAULT 'free';
ALTER TABLE courses ADD COLUMN price DECIMAL(10,2) NOT NULL DEFAULT 0.00;
ALTER TABLE courses ADD COLUMN category VARCHAR(100);
ALTER TABLE courses ADD COLUMN duration VARCHAR(50);
ALTER TABLE courses ADD COLUMN level ENUM('beginner', 'intermediate', 'advanced') DEFAULT 'beginner';
ALTER TABLE courses ADD COLUMN status ENUM('draft', 'published', 'archived') DEFAULT 'draft';
ALTER TABLE courses ADD COLUMN thumbnail VARCHAR(255);
ALTER TABLE courses ADD COLUMN enrollments INT DEFAULT 0;
ALTER TABLE courses ADD COLUMN rating DECIMAL(3,2) DEFAULT 0.00;

-- Tabela de módulos do curso
CREATE TABLE IF NOT EXISTS course_modules (
    id INT PRIMARY KEY AUTO_INCREMENT,
    course_id INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    position INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
);

-- Tabela de aulas
CREATE TABLE IF NOT EXISTS module_lessons (
    id INT PRIMARY KEY AUTO_INCREMENT,
    module_id INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    duration VARCHAR(50),
    video_url VARCHAR(255),
    position INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (module_id) REFERENCES course_modules(id) ON DELETE CASCADE
);

-- Tabela de requisitos do curso
CREATE TABLE IF NOT EXISTS course_requirements (
    id INT PRIMARY KEY AUTO_INCREMENT,
    course_id INT NOT NULL,
    requirement TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
);

-- Tabela de objetivos de aprendizagem
CREATE TABLE IF NOT EXISTS course_learning_goals (
    id INT PRIMARY KEY AUTO_INCREMENT,
    course_id INT NOT NULL,
    goal TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
);

-- Tabela de avaliações do curso
CREATE TABLE IF NOT EXISTS course_reviews (
    id INT PRIMARY KEY AUTO_INCREMENT,
    course_id INT NOT NULL,
    user_id INT NOT NULL,
    rating INT NOT NULL CHECK (rating >= 1 AND rating <= 5),
    comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_review (course_id, user_id)
);

-- Índices para melhorar a performance
CREATE INDEX idx_courses_type ON courses(type);
CREATE INDEX idx_courses_category ON courses(category);
CREATE INDEX idx_courses_status ON courses(status);
CREATE INDEX idx_courses_level ON courses(level);
CREATE INDEX idx_module_lessons_position ON module_lessons(position);
CREATE INDEX idx_course_modules_position ON course_modules(position);

-- Tabela de produtos
CREATE TABLE IF NOT EXISTS products (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL,
    type ENUM('landpage', 'training', 'other') NOT NULL,
    features JSON,
    thumbnail VARCHAR(255),
    status ENUM('active', 'inactive') DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP NULL
);

-- Tabela de pedidos
CREATE TABLE IF NOT EXISTS orders (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    product_id INT NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    status ENUM('pending', 'paid', 'cancelled', 'refunded') DEFAULT 'pending',
    payment_method VARCHAR(50),
    payment_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

-- Tabela de acesso aos produtos
CREATE TABLE IF NOT EXISTS user_products (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    product_id INT NOT NULL,
    order_id INT NOT NULL,
    expires_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id),
    FOREIGN KEY (order_id) REFERENCES orders(id)
); 