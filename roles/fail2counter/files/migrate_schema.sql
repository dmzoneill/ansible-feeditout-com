-- One-time migration: rename old exploits table and recreate with new schema
-- Safe to run multiple times

-- Rename old tables if they exist and new ones don't
SET @old_exists = (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'exploits');
SET @migrated = (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'exploits_legacy');

-- Only migrate if old table exists and hasn't been migrated yet
DROP PROCEDURE IF EXISTS migrate_exploits;
DELIMITER //
CREATE PROCEDURE migrate_exploits()
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'exploits')
       AND NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'exploits_legacy')
       AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'exploits' AND column_name = 'scan_id')
    THEN
        -- Old schema detected (no scan_id column), rename it
        DROP TABLE IF EXISTS exploit_results;
        DROP TABLE IF EXISTS notifications;
        RENAME TABLE exploits TO exploits_legacy;
    END IF;
END //
DELIMITER ;

CALL migrate_exploits();
DROP PROCEDURE IF EXISTS migrate_exploits;
