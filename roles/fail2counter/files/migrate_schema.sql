-- One-time migration: rename old exploits table if it has old schema
-- Safe to run multiple times (PostgreSQL version)

DO $$
BEGIN
    -- Check if exploits table exists but lacks scan_id column (old schema)
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'exploits'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'exploits' AND column_name = 'scan_id'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'exploits_legacy'
    ) THEN
        -- Old schema detected, rename it
        DROP TABLE IF EXISTS exploit_results;
        DROP TABLE IF EXISTS notifications;
        ALTER TABLE exploits RENAME TO exploits_legacy;
    END IF;
END $$;
