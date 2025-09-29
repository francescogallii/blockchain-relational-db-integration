# Sensitive Blockchain Demo

Progetto demo: un database PostgreSQL che memorizza blocchi contenenti dati sensibili in formato chiave/valore (JSON). Ogni payload è cifrato con AES-256-GCM; la chiave simmetrica è cifrata con RSA-OAEP (public key del proprietario). I blocchi sono concatenati tramite prev_hash e ogni blocco è soggetto a Proof-of-Work (difficoltà configurabile).

Struttura:
- /server : backend Node.js (Express) che gestisce la chain e la crittografia
- /client : frontend React minimale per inserire dati e visualizzare la chain

## Requisiti
- Node.js >= 18
- npm
- PostgreSQL in esecuzione

## Setup Server
1. Entrare in `server`:
   ```
   cd server
   npm install
   ```
2. Copiare `.env.sample` in `.env` e impostare la stringa di connessione PostgreSQL:
   ```
   PG_CONN=postgresql://postgres:postgres@localhost:5432/sensitive_chain
   ```
   oppure usare `DATABASE_URL`.

3. Creare il database in Postgres:
   ```
   createdb sensitive_chain
   ```
   (oppure usare pgAdmin/psql)

4. Avviare:
   ```
   npm start
   ```
   Al primo avvio il server creerà la tabella e un **genesis block**. Per scopi demo la chiave privata del genesis viene salvata all'interno del campo `metadata` (NON fare ciò in produzione).

## Setup Client
1. Entrare in `client`:
   ```
   cd client
   npm install
   npm start
   ```
   Il client si avvierà su http://localhost:3000 e comunica con il server su http://localhost:4001 (modificabile con REACT_APP_API).

## API Principali
- `GET /keys/generate` : genera coppia RSA (PEM)
- `POST /blocks/add` : aggiungi blocco. body: `{ payload: {...}, owner_public_key_pem: "..." }`
- `GET /blocks` : lista blocchi (meta)
- `GET /blocks/:idx/verify` : verifica ricomputando hash/Pow fino all'indice
- `POST /blocks/:idx/decrypt` : body `{ private_key_pem: "..." }` per decriptare il payload

## Noteworthy design choices
- Payload chiuso in JSON (chiave-valore) e cifrato interamente. Questo facilita qualsiasi tipo di dato sensibile.
- AES-256-GCM fornisce confidenzialità e integrità; la key è protetta da RSA-OAEP.
- PoW configurabile via `.env` (DIFFICULTY = number of leading hex zeros). Attenzione: valore alto rende il mining pesante.
- Per semplicità e demo, alcune pratiche (es. memorizzare private key) sono presenti; **non** farlo in produzione.

## Limitazioni e avvertenze
- Questo è un progetto dimostrativo: non usare così com'è in produzione senza revisioni di sicurezza.
- Non ho incluso gestione utenti, revoca chiavi, né storage sicuro delle chiavi private.
- La funzione di mining è volutamente semplice: CPU-bound, single-threaded.