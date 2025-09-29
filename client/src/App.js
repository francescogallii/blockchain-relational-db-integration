import React, { useState } from "react";

// Funzioni crittografiche helper (usa WebCrypto API)
async function generateKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["encrypt", "decrypt"]
  );

  const publicKeyPem = await exportKeyToPem(keyPair.publicKey, "PUBLIC KEY");
  const privateKeyPem = await exportKeyToPem(keyPair.privateKey, "PRIVATE KEY");
  return { publicKeyPem, privateKeyPem };
}

async function exportKeyToPem(key, type) {
  const exported = await window.crypto.subtle.exportKey("spki", key).catch(() => window.crypto.subtle.exportKey("pkcs8", key));
  const exportedAsString = String.fromCharCode(...new Uint8Array(exported));
  const exportedAsBase64 = window.btoa(exportedAsString);
  return `-----BEGIN ${type}-----\n${exportedAsBase64}\n-----END ${type}-----`;
}

async function importPublicKey(pem) {
  const pemContents = pem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, "").trim();
  const binaryDer = Uint8Array.from(window.atob(pemContents), c => c.charCodeAt(0));
  return crypto.subtle.importKey("spki", binaryDer.buffer, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);
}

async function importPrivateKey(pem) {
  const pemContents = pem.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, "").trim();
  const binaryDer = Uint8Array.from(window.atob(pemContents), c => c.charCodeAt(0));
  return crypto.subtle.importKey("pkcs8", binaryDer.buffer, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]);
}

async function encryptWithPublicKey(publicKeyPem, plaintext) {
  const key = await importPublicKey(publicKeyPem);
  const enc = new TextEncoder().encode(plaintext);
  const encrypted = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, key, enc);
  return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
}

async function decryptWithPrivateKey(privateKeyPem, ciphertextB64) {
  const key = await importPrivateKey(privateKeyPem);
  const encryptedBytes = Uint8Array.from(atob(ciphertextB64), c => c.charCodeAt(0));
  const decrypted = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, key, encryptedBytes);
  return new TextDecoder().decode(decrypted);
}

// Hash del blocco + PoW
async function calculateHash(data) {
  const enc = new TextEncoder().encode(data);
  const hashBuffer = await crypto.subtle.digest("SHA-256", enc);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function mineBlock(block, difficulty = 4) {
  let nonce = 0;
  let hash = "";
  const prefix = "0".repeat(difficulty);
  do {
    const toHash = block.prevHash + block.timestamp + JSON.stringify(block.data) + block.publicKey + nonce;
    hash = await calculateHash(toHash);
    nonce++;
  } while (!hash.startsWith(prefix));
  block.hash = hash;
  block.nonce = nonce;
  block.valid = true;
  return block;
}

export default function App() {
  const [users, setUsers] = useState([]); // {id, publicKey, privateKey}
  const [nickname, setNickname] = useState("");

  const [chain, setChain] = useState([]); // array di blocchi
  const [newData, setNewData] = useState("");
  const [selectedUser, setSelectedUser] = useState("");

  const [decryptId, setDecryptId] = useState("");
  const [decryptPrivKey, setDecryptPrivKey] = useState("");
  const [decryptedBlocks, setDecryptedBlocks] = useState([]);

  const difficulty = 4;

  async function registerUser() {
    if (!nickname) return;
    // genera chiavi
    const { publicKeyPem, privateKeyPem } = await generateKeyPair();
    const newUser = { id: nickname, publicKey: publicKeyPem, privateKey: privateKeyPem };
    setUsers(prev => [...prev, newUser]);
    setNickname("");
    alert(`Utente ${newUser.id} registrato!\n\nChiave privata:\n${privateKeyPem}`);
  }

  async function addBlock() {
    if (!selectedUser || !newData) return alert("Seleziona utente e inserisci dati");
    const user = users.find(u => u.id === selectedUser);
    if (!user) return;

    const encryptedData = await encryptWithPublicKey(user.publicKey, newData);
    const prevHash = chain.length > 0 ? chain[chain.length - 1].hash : "0".repeat(64);
    const block = {
      index: chain.length,
      timestamp: new Date().toISOString(),
      data: encryptedData,
      publicKey: user.publicKey,
      author: user.id,
      prevHash,
    };

    const mined = await mineBlock(block, difficulty);
    setChain(prev => [...prev, mined]);
    setNewData("");
  }

  async function decryptBlocksForUser() {
    const user = users.find(u => u.id === decryptId);
    if (!user) return alert("Utente non trovato");
    try {
      const results = [];
      for (const b of chain.filter(c => c.author === decryptId)) {
        const dec = await decryptWithPrivateKey(decryptPrivKey, b.data);
        results.push({ hash: b.hash, data: dec, timestamp: b.timestamp });
      }
      setDecryptedBlocks(results);
    } catch (e) {
      alert("Errore nella decifrazione: chiave errata?");
    }
  }

  return (
    <div style={{ fontFamily: "sans-serif", maxWidth: 1000, margin: "0 auto" }}>
      <h2>🔐 Blockchain Sensibile (locale)</h2>

      <section style={sectionStyle}>
        <h3>1️⃣ Registrazione Utente</h3>
        <input placeholder="Nickname" value={nickname} onChange={e => setNickname(e.target.value)} />
        <button onClick={registerUser}>Crea utente & genera chiavi</button>
        <ul>
          {users.map(u => (
            <li key={u.id}>
              <b>{u.id}</b>
            </li>
          ))}
        </ul>
      </section>

      <section style={sectionStyle}>
        <h3>2️⃣ Aggiungi Blocco (con Proof of Work)</h3>
        <select value={selectedUser} onChange={e => setSelectedUser(e.target.value)}>
          <option value="">-- seleziona utente --</option>
          {users.map(u => (
            <option key={u.id} value={u.id}>{u.id}</option>
          ))}
        </select>
        <br />
        <textarea
          rows={4}
          placeholder="Dati sensibili (verranno cifrati con la chiave pubblica dell'utente)"
          value={newData}
          onChange={e => setNewData(e.target.value)}
          style={{ width: "100%", marginTop: 8 }}
        />
        <button onClick={addBlock}>⛏️ Mina & Aggiungi Blocco</button>
      </section>

      <section style={sectionStyle}>
        <h3>3️⃣ Catena di Blocchi</h3>
        {chain.length === 0 && <div>Nessun blocco ancora.</div>}
        {chain.map(b => (
          <div key={b.hash} style={{ border: "1px solid #ccc", padding: 8, marginTop: 8 }}>
            <div><b>Autore:</b> {b.author}</div>
            <div><b>Hash:</b> {b.hash}</div>
            <div><b>PrevHash:</b> {b.prevHash}</div>
            <div><b>Timestamp:</b> {b.timestamp}</div>
            <div><b>Chiave pubblica:</b> <pre style={{whiteSpace:"pre-wrap"}}>{b.publicKey.slice(0,80)}...</pre></div>
            <div><b>Valid:</b> {b.valid ? "✅" : "❌"}</div>
          </div>
        ))}
      </section>

      <section style={sectionStyle}>
        <h3>4️⃣ Decripta Blocchi di un Utente</h3>
        <input placeholder="ID utente" value={decryptId} onChange={e => setDecryptId(e.target.value)} style={{width:"50%"}} />
        <br />
        <textarea
          rows={5}
          placeholder="Chiave privata PEM"
          value={decryptPrivKey}
          onChange={e => setDecryptPrivKey(e.target.value)}
          style={{ width: "100%", marginTop: 8 }}
        />
        <button onClick={decryptBlocksForUser}>🔓 Decripta</button>

        {decryptedBlocks.length > 0 && (
          <div style={{ marginTop: 10 }}>
            <h4>Blocchi decifrati per {decryptId}</h4>
            {decryptedBlocks.map((d, i) => (
              <div key={i} style={{ border: "1px solid #ddd", padding: 8, marginTop: 8 }}>
                <div><b>Hash:</b> {d.hash}</div>
                <div><b>Timestamp:</b> {d.timestamp}</div>
                <div><b>Dati:</b> {d.data}</div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

const sectionStyle = {
  border: "1px solid #ccc",
  padding: 12,
  marginTop: 12,
  borderRadius: 8,
  background: "#f9f9f9",
};
