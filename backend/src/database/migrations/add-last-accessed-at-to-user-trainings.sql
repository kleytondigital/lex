-- Verifica se a coluna não existe antes de criar
SET @dbname = DATABASE();
SET @tablename = "user_trainings";
SET @columnname = "last_accessed_at";
SET @preparedStatement = (SELECT IF(
  (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE
      TABLE_SCHEMA = @dbname
      AND TABLE_NAME = @tablename
      AND COLUMN_NAME = @columnname
  ) > 0,
  "SELECT 1",
  "ALTER TABLE user_trainings ADD COLUMN last_accessed_at datetime DEFAULT NULL AFTER completed_at"
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists; 