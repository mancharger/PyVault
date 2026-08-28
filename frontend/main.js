import argon2 from 'argon2-browser';

// --- DOM Elements ---
const authSection = document.getElementById('authSection');
const vaultSection = document.getElementById('vaultSection');
const masterPasswordInput = document.getElementById('masterPassword');
const unlockBtn = document.getElementById('unlockBtn');
const cryptoLoader = document.getElementById('cryptoLoader');

const noteContent = document.getElementById('noteContent');
const saveNoteBtn = document.getElementById('saveNoteBtn');
const saveLoader = document.getElementById('saveLoader');
const loadNotesBtn = document.getElementById('loadNotesBtn');
const notesList = document.getElementById('notesList');

// Global state for the derived key
let encryptionKey = null;

// --- Cryptographic Functions (Zero-Knowledge) ---

// 1. Derive Key using Argon2
async function deriveKey(password) {
  const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
  
  try {
    const result = await argon2.hash({
      pass: password,
      salt: salt,
      time: 2,
      mem: 1024 * 64,
      hashLen: 32,
      type: argon2.ArgonType.Argon2id
    });
    
    encryptionKey = await window.crypto.subtle.importKey(
      "raw",
      result.hash,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
    
    return true;
  } catch (e) {
    console.error("Falha na derivacao da chave Argon2", e);
    alert("Falha na derivação da chave.");
    return false;
  }
}

function bufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function base64ToBuffer(base64) {
  const binary_string = window.atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}

// 2. Encrypt Note with AES-256-GCM
async function encryptNote(text) {
  const enc = new TextEncoder();
  const encoded = enc.encode(text);
  
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    encryptionKey,
    encoded
  );
  
  return {
    ciphertext: bufferToBase64(ciphertext),
    iv: bufferToBase64(iv),
    salt: bufferToBase64(salt)
  };
}

// 3. Decrypt Note with AES-256-GCM
async function decryptNote(ciphertextB64, ivB64) {
  try {
    const ciphertext = base64ToBuffer(ciphertextB64);
    const iv = base64ToBuffer(ivB64);
    
    const decrypted = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      encryptionKey,
      ciphertext
    );
    
    const dec = new TextDecoder();
    return dec.decode(decrypted);
  } catch (e) {
    console.error("Falha na descriptografia", e);
    return "?O Falha na descriptografia (Senha mestra incorreta?)";
  }
}

// --- Event Listeners & UI Logic ---

unlockBtn.addEventListener('click', async () => {
  const pass = masterPasswordInput.value;
  if (!pass) return alert("Por favor, insira uma senha mestra.");
  
  unlockBtn.disabled = true;
  cryptoLoader.classList.remove('hidden');
  
  setTimeout(async () => {
    const success = await deriveKey(pass);
    cryptoLoader.classList.add('hidden');
    unlockBtn.disabled = false;
    
    if (success) {
      authSection.classList.add('hidden');
      vaultSection.classList.remove('hidden');
    }
  }, 100);
});

saveNoteBtn.addEventListener('click', async () => {
  const text = noteContent.value;
  if (!text) return alert("A nota está vazia.");
  
  saveNoteBtn.disabled = true;
  saveLoader.classList.remove('hidden');
  
  try {
    const encryptedPayload = await encryptNote(text);
    
    const response = await fetch('http://localhost:8000/api/vault/notes/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(encryptedPayload)
    });
    
    if (response.ok) {
      noteContent.value = "";
      alert("Nota criptografada e salva com sucesso!");
    } else {
      alert("Falha ao salvar a nota no servidor.");
    }
  } catch (e) {
    console.error(e);
    alert("Erro de rede ou criptografia.");
  } finally {
    saveLoader.classList.add('hidden');
    saveNoteBtn.disabled = false;
  }
});

loadNotesBtn.addEventListener('click', async () => {
  loadNotesBtn.disabled = true;
  loadNotesBtn.innerText = "Carregando e Descriptografando...";
  
  try {
    const response = await fetch('http://localhost:8000/api/vault/notes/');
    if (!response.ok) throw new Error("Falha ao buscar as notas");
    
    const notes = await response.json();
    notesList.innerHTML = "";
    
    if (notes.length === 0) {
      notesList.innerHTML = "<li>Nenhuma nota segura encontrada.</li>";
    }
    
    for (const note of notes) {
      const decryptedText = await decryptNote(note.ciphertext, note.iv);
      const li = document.createElement('li');
      li.innerText = decryptedText;
      notesList.appendChild(li);
    }
  } catch (e) {
    console.error(e);
    alert("Erro ao buscar as notas.");
  } finally {
    loadNotesBtn.disabled = false;
    loadNotesBtn.innerText = "Buscar e Descriptografar Notas";
  }
});
