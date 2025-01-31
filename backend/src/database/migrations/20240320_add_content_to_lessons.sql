-- Adiciona a coluna content na tabela lessons
ALTER TABLE lessons
ADD COLUMN content TEXT AFTER content_type; 