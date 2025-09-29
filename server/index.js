// server.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(bodyParser.json({ limit: '4mb' }));
app.use(cors());

const pool = new Pool({ connectionString: process.env.DATABASE_URL || process.env.PG_CONN });
const DIFFICULTY = parseInt(process.env.DIFFICULTY || '4', 10);
const MINING_TIMEOUT_MS = parseInt(process.env.MINING_TIMEOUT_MS || '30000', 10);

// ------------------ util ------------------

function parseKeyValueInput(text) {
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
  const obj = {};
  for (const line of lines) {
    const [k, ...rest] = line.split(/\s+/);
    obj[k] = rest.join(' ');
  }
  return obj;
}

// AES-GCM helpers
function aesEncrypt(plaintext) {
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  // store as iv||encrypted||tag (all Buffers)
  return { key, iv, encrypted, tag };
}
function aesDecrypt({ key, iv, encrypted, tag }) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return dec.toString('utf8');
}

// RSA-OAEP wrap/unwrap using Node crypto
function rsaWrap(publicKeyPem, buffer) {
  return crypto.publicEncrypt(
    { key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    buffer
  );
}
function rsaUnwrap(privateKeyPem, buffer) {
  return crypto.privateDecrypt(
    { key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    buffer
  );
}

// sign / verify using RSA-SHA256 (PKCS#1 v1.5)
function signData(privatePem, data) {
  return crypto.sign('sha256', Buffer.from(data), { key: privatePem, padding: crypto.constants.RSA_PKCS1_PADDING });
}
function verifySignature(publicPem, data, signature) {
  return crypto.verify('sha256', Buffer.from(data), { key: publicPem, padding: crypto.constants.RSA_PKCS1_PADDING }, signature);
}

// ------------------ DB init ------------------

async function initDb() {
  const client = await pool.connect();
  try {
    await client.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto;`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS chain_creators (
        creator_id UUID PRIMARY KEY,
        display_name TEXT UNIQUE NOT NULL,
        pgp_public_key TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT now()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS block_chain (
        block_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        encrypted_data BYTEA NOT NULL,
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
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS block_notifications (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        block_id UUID REFERENCES block_chain(block_id) ON DELETE CASCADE,
        creator_id UUID REFERENCES chain_creators(creator_id) ON DELETE CASCADE,
        notified_at TIMESTAMPTZ DEFAULT now(),
        seen BOOLEAN DEFAULT FALSE
      );
    `);

    // create helper SQL function and triggers (if not present)
    await client.query(`
      CREATE OR REPLACE FUNCTION block_hash_fn(previous_hash VARCHAR, encrypted_data BYTEA, created_at TIMESTAMPTZ, nonce BIGINT)
      RETURNS VARCHAR AS $$
        SELECT encode(digest(coalesce(previous_hash, '') || encode(encrypted_data, 'hex') || created_at::TEXT || nonce::TEXT, 'sha256'),'hex');
      $$ LANGUAGE SQL IMMUTABLE;
    `);

    await client.query(`
      CREATE OR REPLACE FUNCTION prevent_update_delete()
      RETURNS trigger AS $$
      BEGIN
        RAISE EXCEPTION 'block_chain is append-only: UPDATE/DELETE prohibited';
      END;
      $$ LANGUAGE plpgsql;
    `);

    await client.query(`DROP TRIGGER IF EXISTS block_chain_protect ON block_chain;`);
    await client.query(`
      CREATE TRIGGER block_chain_protect
      BEFORE UPDATE OR DELETE ON block_chain
      FOR EACH ROW EXECUTE FUNCTION prevent_update_delete();
    `);

    await client.query(`
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
    `);

    await client.query(`DROP TRIGGER IF EXISTS validate_block_insert ON block_chain;`);
    await client.query(`
      CREATE TRIGGER validate_block_insert
      BEFORE INSERT ON block_chain
      FOR EACH ROW EXECUTE FUNCTION validate_block();
    `);

    console.log('DB initialized');
  } finally {
    client.release();
  }
}

// ------------------ API ------------------

// Register creator: { display_name, public_key_pem }
app.post('/creators', async (req, res) => {
  try {
    const { display_name, public_key_pem } = req.body;
    if (!display_name || !public_key_pem) return res.status(400).json({ error: 'display_name and public_key_pem required' });
    const id = crypto.randomUUID();
    await pool.query('INSERT INTO chain_creators (creator_id, display_name, pgp_public_key) VALUES ($1,$2,$3)', [id, display_name, public_key_pem]);
    res.json({ creator_id: id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: String(e.message || e) });
  }
});

// List creators
app.get('/creators', async (req, res) => {
  const r = await pool.query('SELECT creator_id, display_name, created_at FROM chain_creators ORDER BY created_at DESC');
  res.json(r.rows);
});

// List public block headers (joined with creator display_name)
app.get('/blocks', async (req, res) => {
  const q = `
    SELECT b.block_id, b.previous_hash, b.block_hash, b.nonce, b.created_at, b.verified,
           b.creator_id, c.display_name
    FROM block_chain b
    LEFT JOIN chain_creators c ON b.creator_id = c.creator_id
    ORDER BY b.created_at ASC;
  `;
  const r = await pool.query(q);
  res.json(r.rows);
});

// Get single block (public fields)
app.get('/blocks/:block_id', async (req, res) => {
  const r = await pool.query(`
    SELECT b.block_id, b.previous_hash, b.block_hash, b.nonce, b.created_at, b.verified,
           b.creator_id, c.display_name
    FROM block_chain b
    LEFT JOIN chain_creators c ON b.creator_id = c.creator_id
    WHERE b.block_id = $1
  `, [req.params.block_id]);
  if (r.rowCount === 0) return res.status(404).json({ error: 'not found' });
  res.json(r.rows[0]);
});

// Add block (mina lato server)
// Body: { display_name, private_key_pem, data_text }
app.post('/blocks', async (req, res) => {
  try {
    const { display_name, private_key_pem, data_text } = req.body;
    if (!display_name || !private_key_pem || !data_text) return res.status(400).json({ error: 'display_name, private_key_pem, data_text required' });

    // find creator + public key
    const cr = await pool.query('SELECT creator_id, pgp_public_key FROM chain_creators WHERE display_name=$1', [display_name]);
    if (cr.rowCount === 0) return res.status(404).json({ error: 'creator not found' });
    const { creator_id, pgp_public_key } = cr.rows[0];

    // parse KV text -> JSON
    const payloadObj = parseKeyValueInput(data_text);
    const plaintext = JSON.stringify(payloadObj);

    // encrypt payload
    const { key: symKey, iv, encrypted, tag } = aesEncrypt(plaintext);
    const wrappedKey = rsaWrap(pgp_public_key, symKey);

    // store enc as iv||encrypted||tag
    const encBuffer = Buffer.concat([iv, encrypted, tag]);

    // previous hash
    const prevR = await pool.query('SELECT block_hash FROM block_chain ORDER BY created_at DESC LIMIT 1');
    const previousHash = prevR.rowCount ? prevR.rows[0].block_hash : '0'.repeat(64);

    // created_at string (we will pass it to SQL to compute hash consistently)
    const createdAt = new Date().toISOString();

    // mining loop using DB block_hash_fn to guarantee identical hash with DB trigger
    let nonce = 0;
    let foundHash = null;
    const start = Date.now();
    while (true) {
      const q = await pool.query('SELECT block_hash_fn($1, $2, $3::timestamptz, $4) as h', [previousHash, encBuffer, createdAt, nonce]);
      const h = q.rows[0].h;
      if (h.startsWith('0'.repeat(DIFFICULTY))) { foundHash = h; break; }
      nonce++;
      if (nonce % 50000 === 0 && (Date.now() - start) > MINING_TIMEOUT_MS) {
        return res.status(503).json({ error: 'mining timeout; lower DIFFICULTY or increase timeout' });
      }
    }

    // sign the computed hash with provided private key
    const signature = signData(private_key_pem, foundHash);

    // insert block (created_at passed explicitly so DB's created_at::text uses same value)
    const insertQ = `
      INSERT INTO block_chain (created_at, encrypted_data, wrapped_data_key, previous_hash, block_hash, nonce, creator_id, signature, proof_of_work_difficulty)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING block_id, block_hash, nonce, created_at;
    `;
    const insRes = await pool.query(insertQ, [createdAt, encBuffer, wrappedKey, previousHash, foundHash, nonce, creator_id, signature, DIFFICULTY]);
    const block = insRes.rows[0];

    // create notifications for all creators (distribution emulation)
    const allCreators = await pool.query('SELECT creator_id FROM chain_creators');
    if (allCreators.rowCount > 0) {
      const notifyValues = allCreators.rows.map(r => `('${crypto.randomUUID()}', '${block.block_id}', '${r.creator_id}', now(), false)`).join(',');
      // perform single insert
      await pool.query(`INSERT INTO block_notifications (id, block_id, creator_id, notified_at, seen) VALUES ${notifyValues};`);
    }

    res.json({ block_id: block.block_id, block_hash: block.block_hash, nonce: block.nonce, created_at: block.created_at });
  } catch (e) {
    console.error('add block error', e);
    res.status(500).json({ error: String(e.message || e) });
  }
});

// Verify single block: recompute hash via DB function and verify signature, set verified=true if ok
app.post('/blocks/:block_id/verify', async (req, res) => {
  const { block_id } = req.params;
  try {
    const r = await pool.query('SELECT b.block_id, b.previous_hash, b.encrypted_data, b.created_at, b.nonce, b.block_hash, b.proof_of_work_difficulty, b.signature, c.pgp_public_key FROM block_chain b LEFT JOIN chain_creators c ON b.creator_id = c.creator_id WHERE b.block_id=$1', [block_id]);
    if (r.rowCount === 0) return res.status(404).json({ error: 'block not found' });
    const row = r.rows[0];

    // compute via DB function (guaranteed same representation)
    const q = await pool.query('SELECT block_hash_fn($1, $2, $3::timestamptz, $4) AS computed', [row.previous_hash, row.encrypted_data, row.created_at, row.nonce]);
    const computed = q.rows[0].computed;
    if (computed !== row.block_hash) return res.status(400).json({ verified: false, reason: 'block_hash mismatch', computed, stored: row.block_hash });

    // check PoW prefix
    const target = '0'.repeat(row.proof_of_work_difficulty || DIFFICULTY);
    if (!row.block_hash.startsWith(target)) return res.status(400).json({ verified: false, reason: 'insufficient PoW' });

    // verify signature (needs creator public key)
    if (!row.pgp_public_key) return res.status(400).json({ verified: false, reason: 'creator public key missing' });
    const sigOk = verifySignature(row.pgp_public_key, row.block_hash, row.signature);
    if (!sigOk) return res.status(400).json({ verified: false, reason: 'signature invalid' });

    // mark verified
    await pool.query('UPDATE block_chain SET verified = true WHERE block_id=$1', [block_id]);
    res.json({ verified: true, block_id });
  } catch (e) {
    console.error('verify error', e);
    res.status(500).json({ error: String(e.message || e) });
  }
});

// Decrypt all blocks for a user
// Body: { display_name, private_key_pem }
app.post('/decrypt', async (req, res) => {
  try {
    const { display_name, private_key_pem } = req.body;
    if (!display_name || !private_key_pem) return res.status(400).json({ error: 'display_name and private_key_pem required' });

    const cr = await pool.query('SELECT creator_id, pgp_public_key FROM chain_creators WHERE display_name=$1', [display_name]);
    if (cr.rowCount === 0) return res.status(404).json({ error: 'creator not found' });
    const creator_id = cr.rows[0].creator_id;

    const blocks = await pool.query('SELECT block_id, encrypted_data, wrapped_data_key, created_at FROM block_chain WHERE creator_id=$1 ORDER BY created_at ASC', [creator_id]);
    const out = [];
    for (const b of blocks.rows) {
      try {
        const encBuf = b.encrypted_data; // Buffer
        const iv = encBuf.slice(0, 12);
        const tag = encBuf.slice(encBuf.length - 16);
        const cipher = encBuf.slice(12, encBuf.length - 16);
        const sym = rsaUnwrap(private_key_pem, b.wrapped_data_key);
        const plaintext = aesDecrypt({ key: sym, iv, encrypted: cipher, tag });
        out.push({ block_id: b.block_id, created_at: b.created_at, data: JSON.parse(plaintext) });
      } catch (e) {
        out.push({ block_id: b.block_id, error: 'decryption_failed' });
      }
    }
    res.json(out);
  } catch (e) {
    console.error('decrypt error', e);
    res.status(500).json({ error: String(e.message || e) });
  }
});

// Notifications: poll unseen notifications for a creator
app.get('/notifications', async (req, res) => {
  const { creator_id } = req.query;
  if (!creator_id) return res.status(400).json({ error: 'creator_id required' });
  const q = `
    SELECT n.id, n.block_id, n.notified_at, n.seen, b.block_hash, b.previous_hash, b.created_at, c.display_name AS creator_name
    FROM block_notifications n
    JOIN block_chain b ON n.block_id = b.block_id
    LEFT JOIN chain_creators c ON b.creator_id = c.creator_id
    WHERE n.creator_id = $1 AND n.seen = false
    ORDER BY n.notified_at ASC
  `;
  const r = await pool.query(q, [creator_id]);
  res.json(r.rows);
});

app.post('/notifications/:id/mark-seen', async (req, res) => {
  const id = req.params.id;
  await pool.query('UPDATE block_notifications SET seen = true WHERE id = $1', [id]);
  res.json({ ok: true });
});

// Key generation helper
app.get('/keys/generate', (req, res) => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  res.json({
    publicKey: publicKey.export({ type: 'pkcs1', format: 'pem' }),
    privateKey: privateKey.export({ type: 'pkcs1', format: 'pem' })
  });
});

// health
app.get('/', (req, res) => res.json({ ok: true }));

// start
const PORT = process.env.PORT || 4001;
initDb().then(() => {
  app.listen(PORT, () => console.log(`Server running on ${PORT}`));
}).catch(err => {
  console.error('DB init error', err);
  process.exit(1);
});
