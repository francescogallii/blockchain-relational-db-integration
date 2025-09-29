-- migration.sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- creators (display_name unique)
CREATE TABLE IF NOT EXISTS chain_creators (
    creator_id UUID PRIMARY KEY,
    display_name TEXT UNIQUE NOT NULL,
    pgp_public_key TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- block_chain (con verified)
CREATE TABLE IF NOT EXISTS block_chain (
    block_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    encrypted_data BYTEA NOT NULL,        -- stored as iv||ciphertext||tag
    wrapped_data_key BYTEA NOT NULL,
    previous_hash VARCHAR(64),
    block_hash VARCHAR(64) NOT NULL,
    nonce BIGINT NOT NULL,
    creator_id UUID REFERENCES chain_creators(creator_id) ON DELETE SET NULL,
    signature BYTEA NOT NULL,
    proof_of_work_difficulty INTEGER NOT NULL DEFAULT 4,
    verified BOOLEAN DEFAULT FALSE,
    inserted_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_block_chain_created_at ON block_chain(created_at DESC);

-- Notifications table to emulate distribution
CREATE TABLE IF NOT EXISTS block_notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    block_id UUID REFERENCES block_chain(block_id) ON DELETE CASCADE,
    creator_id UUID REFERENCES chain_creators(creator_id) ON DELETE CASCADE,
    notified_at TIMESTAMPTZ DEFAULT now(),
    seen BOOLEAN DEFAULT FALSE
);

-- block_hash_fn (used for consistent hashing)
CREATE OR REPLACE FUNCTION block_hash_fn(
    previous_hash VARCHAR,
    encrypted_data BYTEA,
    created_at TIMESTAMPTZ,
    nonce BIGINT
) RETURNS VARCHAR AS $$
    SELECT encode(
        digest(
            coalesce(previous_hash, '') || encode(encrypted_data, 'hex') || created_at::TEXT || nonce::TEXT,
            'sha256'
        ),
        'hex'
    );
$$ LANGUAGE SQL IMMUTABLE;

-- protect table from UPDATE/DELETE
CREATE OR REPLACE FUNCTION prevent_update_delete()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'block_chain is append-only: UPDATE/DELETE prohibited';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS block_chain_protect ON block_chain;
CREATE TRIGGER block_chain_protect
BEFORE UPDATE OR DELETE ON block_chain
FOR EACH ROW EXECUTE FUNCTION prevent_update_delete();

-- validate_block (partial validation; app does heavy lifting but DB still defends)
CREATE OR REPLACE FUNCTION validate_block()
RETURNS trigger AS $$
DECLARE
    last_hash VARCHAR;
    computed_hash VARCHAR;
    target_prefix TEXT;
    last_block_count INT;
BEGIN
    IF NEW.wrapped_data_key IS NULL THEN
        RAISE EXCEPTION 'wrapped_data_key is required';
    END IF;
    IF NEW.signature IS NULL THEN
        RAISE EXCEPTION 'signature is required';
    END IF;

    SELECT COUNT(*) INTO last_block_count FROM block_chain;
    IF last_block_count > 0 THEN
        SELECT block_hash INTO last_hash
        FROM block_chain
        ORDER BY created_at DESC, inserted_at DESC
        LIMIT 1;

        IF NEW.previous_hash IS DISTINCT FROM last_hash THEN
            RAISE EXCEPTION 'Invalid previous_hash: must equal last block''s hash';
        END IF;
    ELSE
        IF NEW.previous_hash IS NOT NULL AND NEW.previous_hash != repeat('0',64) THEN
            RAISE EXCEPTION 'Genesis block must have previous_hash NULL or zero-hash';
        END IF;
    END IF;

    computed_hash := block_hash_fn(NEW.previous_hash, NEW.encrypted_data, NEW.created_at, NEW.nonce);
    IF computed_hash IS DISTINCT FROM NEW.block_hash THEN
        RAISE EXCEPTION 'block_hash mismatch: computed % vs provided %', computed_hash, NEW.block_hash;
    END IF;

    target_prefix := repeat('0', NEW.proof_of_work_difficulty);
    IF left(NEW.block_hash, NEW.proof_of_work_difficulty) != target_prefix THEN
        RAISE EXCEPTION 'Proof-of-Work not satisfied';
    END IF;

    IF NEW.creator_id IS NOT NULL THEN
        IF NOT EXISTS (SELECT 1 FROM chain_creators WHERE creator_id = NEW.creator_id) THEN
            RAISE EXCEPTION 'creator_id % not registered', NEW.creator_id;
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS validate_block_insert ON block_chain;
CREATE TRIGGER validate_block_insert
BEFORE INSERT ON block_chain
FOR EACH ROW EXECUTE FUNCTION validate_block();
