import React, { useEffect, useState } from "react";

const API_BASE = process.env.REACT_APP_API_BASE || "http://localhost:4001";

async function generateKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );

  const publicKeyPem = await exportKeyToPem(keyPair.publicKey);
  const privateKeyPem = await exportKeyToPem(keyPair.privateKey);
  return { publicKeyPem, privateKeyPem };
}

async function exportKeyToPem(key) {
  if (key.type === "public") {
    const exported = await window.crypto.subtle.exportKey("spki", key);
    const exportedAsString = String.fromCharCode(...new Uint8Array(exported));
    const exportedAsBase64 = window.btoa(exportedAsString);
    return `-----BEGIN PUBLIC KEY-----\n${chunkBase64(exportedAsBase64)}\n-----END PUBLIC KEY-----`;
  } else if (key.type === "private") {
    const exported = await window.crypto.subtle.exportKey("pkcs8", key);
    const exportedAsString = String.fromCharCode(...new Uint8Array(exported));
    const exportedAsBase64 = window.btoa(exportedAsString);
    return `-----BEGIN PRIVATE KEY-----\n${chunkBase64(exportedAsBase64)}\n-----END PRIVATE KEY-----`;
  }
  throw new Error("Unknown key type");
}

function chunkBase64(b64) {
  return b64.match(/.{1,64}/g).join("\n");
}

export default function App() {
  const [creators, setCreators] = useState([]);
  const [nickname, setNickname] = useState("");
  const [loading, setLoading] = useState(false);
  const [selectedCreator, setSelectedCreator] = useState("");
  const [dataText, setDataText] = useState("");
  const [privateKeyInput, setPrivateKeyInput] = useState("");
  const [chain, setChain] = useState([]);
  const [decryptResults, setDecryptResults] = useState([]);
  const [decryptLoading, setDecryptLoading] = useState(false);
  const [decryptPrivateKeyInput, setDecryptPrivateKeyInput] = useState("");
  const [decryptNickname, setDecryptNickname] = useState("");

  useEffect(() => {
    fetchCreators();
    fetchBlocks();
    const interval = setInterval(() => fetchBlocks(), 5000);
    return () => clearInterval(interval);
  }, []);

  async function fetchCreators() {
    try {
      const r = await fetch(`${API_BASE}/creators`);
      const json = await r.json();
      setCreators(json);
    } catch (e) {
      console.error("fetch creators err", e);
    }
  }

  async function fetchBlocks() {
    try {
      const r = await fetch(`${API_BASE}/blocks`);
      const json = await r.json();
      setChain(json);
    } catch (e) {
      console.error("fetch blocks err", e);
    }
  }

  async function handleRegister() {
    if (!nickname) return alert("Inserisci un nickname");
    setLoading(true);
    try {
      const { publicKeyPem, privateKeyPem } = await generateKeyPair();
      const r = await fetch(`${API_BASE}/creators`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ display_name: nickname, public_key_pem: publicKeyPem }),
      });
      const json = await r.json();
      if (!r.ok) throw new Error(json.error || JSON.stringify(json));
      setNickname("");
      await fetchCreators();
      alert(`Utente registrato. Salva la chiave privata in un posto sicuro.\n\nChiave privata:\n\n${privateKeyPem}`);
    } catch (e) {
      console.error(e);
      alert("Errore registrazione: " + (e.message || e));
    } finally {
      setLoading(false);
    }
  }

  async function handleAddBlock() {
    if (!selectedCreator) return alert("Seleziona un creator");
    if (!dataText) return alert("Inserisci dati");
    if (!privateKeyInput) return alert("Inserisci la chiave privata");
    setLoading(true);
    try {
      const r = await fetch(`${API_BASE}/blocks`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          display_name: selectedCreator,
          private_key_pem: privateKeyInput,
          data_text: dataText,
        }),
      });
      const json = await r.json();
      if (!r.ok) throw new Error(json.error || JSON.stringify(json));
      setDataText("");
      setPrivateKeyInput("");
      await fetchBlocks();
      alert(`Blocco creato: ${json.block_hash}`);
    } catch (e) {
      console.error(e);
      alert("Errore creazione blocco: " + (e.message || e));
    } finally {
      setLoading(false);
    }
  }

  async function handleDecrypt() {
    if (!decryptNickname) return alert("Inserisci nickname");
    if (!decryptPrivateKeyInput) return alert("Inserisci la chiave privata");
    setDecryptLoading(true);
    try {
      const r = await fetch(`${API_BASE}/decrypt`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          display_name: decryptNickname,
          private_key_pem: decryptPrivateKeyInput,
        }),
      });
      const json = await r.json();
      if (!r.ok) throw new Error(json.error || JSON.stringify(json));
      setDecryptResults(json);
    } catch (e) {
      console.error(e);
      alert("Errore decrypt: " + (e.message || e));
    } finally {
      setDecryptLoading(false);
    }
  }

  return (
    <div style={{ fontFamily: "sans-serif", maxWidth: 1000, margin: "0 auto" }}>
      <h1>Blockchain DB</h1>

      {/* Registrazione */}
      <section style={sectionStyle}>
        <h3>Registrazione Utente</h3>
        <input placeholder="Nickname" value={nickname} onChange={e => setNickname(e.target.value)} />
        <button onClick={handleRegister} disabled={loading}>Registra e genera chiavi</button>
        <ul>
          {creators.map(c => (
            <li key={c.creator_id}>
              <b>{c.display_name}</b> — <small>{new Date(c.created_at).toLocaleString()}</small>
            </li>
          ))}
        </ul>
      </section>

      {/* Aggiungi Blocco */}
      <section style={sectionStyle}>
        <h3>Aggiungi Blocco</h3>
        <select value={selectedCreator} onChange={e => setSelectedCreator(e.target.value)}>
          <option value="">-- seleziona creator --</option>
          {creators.map(c => (
            <option key={c.creator_id} value={c.display_name}>{c.display_name}</option>
          ))}
        </select>
        <textarea rows={4} value={dataText} onChange={e => setDataText(e.target.value)} placeholder="Testo key-value" />
        <textarea rows={5} value={privateKeyInput} onChange={e => setPrivateKeyInput(e.target.value)} placeholder="Chiave privata PEM" style={{ fontFamily: "monospace" }} />
        <button onClick={handleAddBlock} disabled={loading}>Mina & Aggiungi</button>
      </section>

      {/* Blockchain */}
      <section style={sectionStyle}>
        <h3>Catena di blocchi</h3>
        {chain.length === 0 && <div>Nessun blocco</div>}
        {chain.map(b => (
          <div key={b.block_id} style={{ border: "1px solid #ccc", padding: 8, marginTop: 8 }}>
            <div><b>Autore:</b> {b.display_name || b.creator_id}</div>
            <div><b>Hash:</b> {b.block_hash}</div>
            <div><b>PrevHash:</b> {b.previous_hash}</div>
            <div><b>Timestamp:</b> {new Date(b.created_at).toLocaleString()}</div>
            <div><b>Nonce:</b> {b.nonce}</div>
            <div><b>Verified:</b> {b.verified ? "✅" : "❌"}</div>
          </div>
        ))}
      </section>

      {/* Decrypt */}
      <section style={sectionStyle}>
        <h3>Decrypt</h3>
        <input type="text" placeholder="Nickname" value={decryptNickname} onChange={e => setDecryptNickname(e.target.value)} />
        <textarea rows={5} value={decryptPrivateKeyInput} onChange={e => setDecryptPrivateKeyInput(e.target.value)} placeholder="Chiave privata PEM" style={{ fontFamily: "monospace" }} />
        <button onClick={handleDecrypt}>Decripta blocchi</button>
        {decryptLoading && <div>Decifrando...</div>}
        {decryptResults.length > 0 && (
          <div>
            <h4>Risultati</h4>
            {decryptResults.map((r, i) => (
              <div key={i} style={{ border: "1px solid #ddd", padding: 8, marginTop: 8 }}>
                <div><b>Block:</b> {r.block_id}</div>
                <div><b>Data:</b> <pre>{JSON.stringify(r.data || r.error, null, 2)}</pre></div>
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
