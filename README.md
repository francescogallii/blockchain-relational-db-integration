# 🧱 Blockchain DB — Installazione e Avvio su Arch Linux

Questo progetto implementa una semplice blockchain **append-only** basata su **PostgreSQL**, con backend Node.js e frontend React.  
Segue una guida passo-passo per installare, configurare e avviare il sistema da zero su **Arch Linux**.

---

## 📦 1. Installazione dei Prerequisiti

### 1.1 Installa PostgreSQL
```bash
sudo pacman -S postgresql
````

### 1.2 Installa Node.js e npm

```bash
sudo pacman -S nodejs npm
```

### 1.3 (Consigliato) Installa NVM + Node 20

Create React App non supporta Node 24, quindi usiamo la versione 20.

```bash
sudo pacman -S nvm
nvm install 20
nvm use 20
node --version    # deve risultare v20.x.x
```

---

## 🗃 2. Configurazione del Database PostgreSQL

### 2.1 Inizializza il cluster (solo la prima volta)

```bash
sudo -iu postgres
initdb --locale=it_IT.UTF-8 -D /var/lib/postgres/data
exit
```

### 2.2 Avvia PostgreSQL e abilita all'avvio

```bash
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

### 2.3 Crea utente e database

```bash
sudo -iu postgres
createuser --interactive   # es: "francesco"
createdb --owner=postgres blockchain_db
exit
```

*(In alternativa puoi usare l’utente predefinito `postgres`.)*

---

## 🧠 2.4 Importa lo Schema SQL

Crea un file chiamato `schema.sql` nella root del progetto e incolla al suo interno lo **schema completo** (tabelle, indici, trigger e funzioni per validazione blockchain).

Poi importa lo schema:

```bash
psql -U postgres -d blockchain_db -f schema.sql
```

Se tutto va a buon fine, il database sarà pronto per essere usato dal backend.

---

## 🖥 3. Backend Node.js

### 3.1 Vai nella cartella del backend

```bash
cd /percorso/backend
```

### 3.2 Crea il file `.env`

```bash
nano .env
```

Inserisci:

```
DATABASE_URL=postgresql://postgres@localhost:5432/blockchain_db
DIFFICULTY=4
MINING_TIMEOUT_MS=30000
PORT=4001
```

*(Modifica l’utente se non usi `postgres`.)*

### 3.3 Installa le dipendenze

```bash
npm install
```

### 3.4 Avvia il backend

```bash
npm start
# oppure
node server.js
```

Se non appaiono errori, la connessione al DB è corretta ✅

---

## 🌐 4. Frontend React

### 4.1 Vai nella cartella del frontend

```bash
cd /percorso/frontend
```

### 4.2 Crea il file `.env`

```bash
nano .env
```

Inserisci:

```
REACT_APP_API_BASE=http://localhost:4001
```

### 4.3 Controlla `package.json`

Deve contenere:

```json
"dependencies": {
  "react": "...",
  "react-dom": "...",
  "react-scripts": "^5.0.1"
}
```

### 4.4 Installa dipendenze

```bash
rm -rf node_modules package-lock.json
npm install
```

### 4.5 Avvia il frontend

```bash
npm start
```

👉 Si aprirà automaticamente [http://localhost:3000](http://localhost:3000).

---

## 🧪 5. Verifiche Utili

### Controlla contenuto del DB

```bash
psql -U francesco -d blockchain_db
\dt                            # Vedi le tabelle
SELECT * FROM block_chain;     # Vedi i blocchi
SELECT * FROM chain_creators;  # Vedi gli utenti
\q
```

### Svuota il database

```bash
psql -U francesco -d blockchain_db
TRUNCATE chain_creators, block_chain, block_notifications RESTART IDENTITY CASCADE;
\q
```

### Gestione servizio PostgreSQL

```bash
sudo systemctl stop postgresql
sudo systemctl start postgresql
```

---

## ✅ 6. Avvio Completo

Ordine consigliato:

1. ✅ Avvia PostgreSQL
2. ✅ Importa lo schema SQL
3. ✅ Avvia **backend** (`npm start`)
4. ✅ Avvia **frontend** (`npm start`)
5. 🌐 Apri [http://localhost:3000](http://localhost:3000) e interagisci!

---

## 🧹 7. Reset Totale del Sistema

### 7.1 Elimina e ricrea il database

```bash
sudo -iu postgres
dropdb blockchain_db
createdb --owner=postgres blockchain_db
exit
```

### 7.2 Oppure elimina solo le tabelle

```bash
psql -U postgres -d blockchain_db
DROP TABLE IF EXISTS block_notifications, block_chain, chain_creators CASCADE;
\q
```

Poi reimporta `schema.sql`.

---

### 7.3 Elimina backend e frontend

```bash
rm -rf /percorso/backend/node_modules /percorso/backend/package-lock.json
rm -rf /percorso/frontend/node_modules /percorso/frontend/package-lock.json
```

Oppure per rimuovere completamente:

```bash
rm -rf /percorso/backend
rm -rf /percorso/frontend
```

### 7.4 Ri-clona il repository

```bash
git clone https://url/del/tuo/repo.git
cd nomecartella
```

---

## 🚀 8. Riavvio Rapido

* **Backend:**

```bash
cd /percorso/backend
npm start
```

* **Frontend:**

```bash
cd /percorso/frontend
npm start
```

* **Database:**

```bash
sudo systemctl start postgresql
```

---

## 📝 Licenza

Puoi adattare questa guida liberamente.
Suggerito: [MIT License](https://opensource.org/licenses/MIT)

---

## 📚 Riferimenti

* [PostgreSQL Docs](https://www.postgresql.org/docs/)
* [Node.js](https://nodejs.org/)
* [React](https://react.dev/)
* [pgcrypto Extension](https://www.postgresql.org/docs/current/pgcrypto.html)
