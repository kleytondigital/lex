CREATE TABLE IF NOT EXISTS landing_page_media (
    id INT AUTO_INCREMENT PRIMARY KEY,
    landing_page_id INT NOT NULL,
    url VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (landing_page_id) REFERENCES landing_pages(id) ON DELETE CASCADE
); 