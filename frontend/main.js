import argon2 from 'argon2-browser/dist/argon2-bundled.min.js';
import QRCode from 'qrcode';

// --- DOM Elements ---
const authSection = document.getElementById('authSection');
const vaultSection = document.getElementById('vaultSection');
const mfaSetupSection = document.getElementById('mfaSetupSection');

const usernameInput = document.getElementById('usernameInput');
const masterPasswordInput = document.getElementById('masterPasswordInput');
const loginBtn = document.getElementById('loginBtn');
const registerBtn = document.getElementById('registerBtn');
const authLoader = document.getElementById('authLoader');
const headerStatus = document.getElementById('headerStatus');
const logoutBtn = document.getElementById('logoutBtn');

// MFA Elements
const mfaPromptSection = document.getElementById('mfaPromptSection');
const mfaCodeInput = document.getElementById('mfaCodeInput');
const mfaVerifyBtn = document.getElementById('mfaVerifyBtn');
const mfaQrCode = document.getElementById('mfaQrCode');
const mfaSetupCodeInput = document.getElementById('mfaSetupCodeInput');
const mfaSetupConfirmBtn = document.getElementById('mfaSetupConfirmBtn');

// Dashboard Tabs
const tabBtns = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');

// Notes
const noteContent = document.getElementById('noteContent');
const saveNoteBtn = document.getElementById('saveNoteBtn');
const loadNotesBtn = document.getElementById('loadNotesBtn');
const notesList = document.getElementById('notesList');

// Passwords
const pwTitle = document.getElementById('pwTitle');
const pwUser = document.getElementById('pwUser');
const pwPass = document.getElementById('pwPass');
const pwUrl = document.getElementById('pwUrl');
const savePasswordBtn = document.getElementById('savePasswordBtn');
const loadPasswordsBtn = document.getElementById('loadPasswordsBtn');
const passwordsList = document.getElementById('passwordsList');

// Global state
let encryptionKey = null;
let authKeyHex = null;
let jwtToken = null;

// --- Cryptographic Functions (Zero-Knowledge) ---

// 1. Derive Keys using Argon2 (64 bytes total -> 32 auth, 32 enc)
async function deriveKeys(password, username) {
  // Use username as salt (padded to 16 bytes for uniqueness per user)
  let saltStr = (username + "PyVaultSaltString").substring(0, 16);
  const enc = new TextEncoder();
  const salt = enc.encode(saltStr);
  
  try {
    const result = await argon2.hash({
      pass: password,
      salt: salt,
      time: 2,
      mem: 1024 * 64,
      hashLen: 64, // 64 bytes total
      type: argon2.ArgonType.Argon2id
    });
    
    // Convert to hex string
    const rawHash = result.hash;
    
    // Split: 32 bytes for auth, 32 bytes for encryption
    const authBytes = rawHash.slice(0, 32);
    const encBytes = rawHash.slice(32, 64);
    
    authKeyHex = bufferToHex(authBytes);
    
    encryptionKey = await window.crypto.subtle.importKey(
      "raw",
      encBytes,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
    
    return true;
  } catch (e) {
    console.error("Falha na derivacao Argon2", e);
    return false;
  }
}

function bufferToHex(buffer) {
  return Array.from(buffer).map(b => b.toString(16).padStart(2, '0')).join('');
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

// 2. Encrypt Generic Payload with AES-256-GCM
async function encryptPayload(payloadObj) {
  const enc = new TextEncoder();
  const encoded = enc.encode(JSON.stringify(payloadObj));
  
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

// 3. Decrypt Generic Payload
async function decryptPayload(ciphertextB64, ivB64) {
  try {
    const ciphertext = base64ToBuffer(ciphertextB64);
    const iv = base64ToBuffer(ivB64);
    
    const decrypted = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      encryptionKey,
      ciphertext
    );
    
    const dec = new TextDecoder();
    return JSON.parse(dec.decode(decrypted));
  } catch (e) {
    console.error("Falha na descriptografia", e);
    return { error: "Falha na descriptografia (Chave incorreta?)" };
  }
}

// --- Fetch Wrapper with Auth ---
async function fetchApi(endpoint, options = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (jwtToken) {
    headers['Authorization'] = `Bearer ${jwtToken}`;
  }
  options.headers = { ...headers, ...options.headers };
  return fetch(`http://localhost:8000/api${endpoint}`, options);
}

// --- Auth Flows ---
registerBtn.addEventListener('click', async () => {
  const user = usernameInput.value;
  const pass = masterPasswordInput.value;
  if (!user || !pass) return alert("Usuário e Senha são obrigatórios.");
  
  authLoader.classList.remove('hidden');
  await deriveKeys(pass, user);
  
  try {
    const res = await fetchApi('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ username: user, auth_key: authKeyHex })
    });
    const data = await res.json();
    if (res.ok) {
      jwtToken = data.access_token;
      showMfaSetup();
    } else {
      alert(data.detail || "Erro ao registrar");
    }
  } catch (e) {
    alert("Erro de rede");
  } finally {
    authLoader.classList.add('hidden');
  }
});

let pendingLoginData = null;

loginBtn.addEventListener('click', async () => {
  const user = usernameInput.value;
  const pass = masterPasswordInput.value;
  if (!user || !pass) return alert("Usuário e Senha são obrigatórios.");
  
  authLoader.classList.remove('hidden');
  await deriveKeys(pass, user);
  
  pendingLoginData = { username: user, auth_key: authKeyHex };
  await attemptLogin(pendingLoginData);
});

async function attemptLogin(payload) {
  try {
    const res = await fetchApi('/auth/login', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (res.ok) {
      if (data.mfa_required) {
        mfaPromptSection.classList.remove('hidden');
      } else {
        jwtToken = data.access_token;
        enterVault();
      }
    } else {
      alert(data.detail || "Credenciais inválidas");
    }
  } catch (e) {
    alert("Erro de rede");
  } finally {
    authLoader.classList.add('hidden');
  }
}

mfaVerifyBtn.addEventListener('click', async () => {
  const code = mfaCodeInput.value;
  if (code.length !== 6) return alert("Código inválido");
  
  pendingLoginData.mfa_code = code;
  await attemptLogin(pendingLoginData);
});

// --- MFA Setup Flow ---
async function showMfaSetup() {
  authSection.classList.add('hidden');
  mfaSetupSection.classList.remove('hidden');
  
  const res = await fetchApi('/auth/mfa/setup', { method: 'POST' });
  const data = await res.json();
  
  QRCode.toCanvas(mfaQrCode, data.uri, function (error) {
    if (error) console.error(error)
  });
}

mfaSetupConfirmBtn.addEventListener('click', async () => {
  const code = mfaSetupCodeInput.value;
  const res = await fetchApi('/auth/mfa/verify', {
    method: 'POST',
    body: JSON.stringify({ code: code })
  });
  
  if (res.ok) {
    alert("MFA Ativado com sucesso!");
    mfaSetupSection.classList.add('hidden');
    enterVault();
  } else {
    alert("Código inválido");
  }
});

function enterVault() {
  authSection.classList.add('hidden');
  mfaSetupSection.classList.add('hidden');
  vaultSection.classList.remove('hidden');
  
  headerStatus.innerText = "Cofre Desbloqueado";
  headerStatus.style.color = "var(--primary-color)";
  logoutBtn.classList.remove('hidden');
}

logoutBtn.addEventListener('click', () => {
  jwtToken = null;
  encryptionKey = null;
  authKeyHex = null;
  window.location.reload();
});

// --- Tab Logic ---
tabBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    tabBtns.forEach(b => b.classList.remove('active'));
    tabContents.forEach(c => c.classList.remove('active'));
    
    btn.classList.add('active');
    document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
  });
});

// --- Notes Logic ---
saveNoteBtn.addEventListener('click', async () => {
  const text = noteContent.value;
  if (!text) return alert("Nota vazia");
  
  const payload = await encryptPayload({ text });
  const res = await fetchApi('/vault/notes/', { method: 'POST', body: JSON.stringify(payload) });
  
  if (res.ok) {
    alert("Nota salva de forma segura!");
    noteContent.value = "";
  } else {
    alert("Erro ao salvar nota");
  }
});

loadNotesBtn.addEventListener('click', async () => {
  const res = await fetchApi('/vault/notes/');
  if (!res.ok) return alert("Erro ao buscar notas");
  const notes = await res.json();
  
  notesList.innerHTML = "";
  for (const n of notes) {
    const dec = await decryptPayload(n.ciphertext, n.iv);
    const li = document.createElement('li');
    li.innerText = dec.text || dec.error;
    notesList.appendChild(li);
  }
});

// --- Passwords Logic ---
savePasswordBtn.addEventListener('click', async () => {
  const obj = {
    title: pwTitle.value,
    user: pwUser.value,
    pass: pwPass.value,
    url: pwUrl.value
  };
  if (!obj.title || !obj.pass) return alert("Título e Senha são obrigatórios");
  
  const payload = await encryptPayload(obj);
  const res = await fetchApi('/vault/passwords/', { method: 'POST', body: JSON.stringify(payload) });
  
  if (res.ok) {
    alert("Senha salva e criptografada!");
    pwTitle.value = pwUser.value = pwPass.value = pwUrl.value = "";
  }
});

loadPasswordsBtn.addEventListener('click', async () => {
  const res = await fetchApi('/vault/passwords/');
  if (!res.ok) return alert("Erro ao buscar senhas");
  const pws = await res.json();
  
  passwordsList.innerHTML = "";
  for (const p of pws) {
    const dec = await decryptPayload(p.ciphertext, p.iv);
    const li = document.createElement('li');
    if (dec.error) {
      li.innerText = dec.error;
    } else {
      li.innerHTML = `<strong>${dec.title}</strong><br>Usuário: ${dec.user}<br>Senha: ${dec.pass}<br>${dec.url}`;
    }
    passwordsList.appendChild(li);
  }
});
