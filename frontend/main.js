import argon2 from 'argon2-browser';
import QRCode from 'qrcode';

// --- Toast System ---
function showToast(message, type = 'success') {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerText = message;
  container.appendChild(toast);
  
  // Remove after animation (4.3s total)
  setTimeout(() => {
    if(container.contains(toast)) {
      container.removeChild(toast);
    }
  }, 4300);
}

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
const noteTitle = document.getElementById('noteTitle');
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

// Files
const fileInput = document.getElementById('fileInput');
const uploadFileBtn = document.getElementById('uploadFileBtn');
const loadFilesBtn = document.getElementById('loadFilesBtn');
const filesList = document.getElementById('filesList');

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
  if (!user || !pass) return showToast("Usuário e Senha são obrigatórios.", "error");
  
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
      showToast(data.detail || "Erro ao registrar", "error");
    }
  } catch (e) {
    showToast("Erro de rede", "error");
  } finally {
    authLoader.classList.add('hidden');
  }
});

let pendingLoginData = null;

loginBtn.addEventListener('click', async () => {
  const user = usernameInput.value;
  const pass = masterPasswordInput.value;
  if (!user || !pass) return showToast("Usuário e Senha são obrigatórios.", "error");
  
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
        showToast("Insira seu código MFA.", "success");
      } else {
        jwtToken = data.access_token;
        enterVault();
      }
    } else {
      showToast(data.detail || "Credenciais inválidas", "error");
    }
  } catch (e) {
    showToast("Erro de rede", "error");
  } finally {
    authLoader.classList.add('hidden');
  }
}

mfaVerifyBtn.addEventListener('click', async () => {
  const code = mfaCodeInput.value;
  if (code.length !== 6) return showToast("Código inválido", "error");
  
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
    showToast("MFA Ativado com sucesso!", "success");
    mfaSetupSection.classList.add('hidden');
    enterVault();
  } else {
    showToast("Código inválido", "error");
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

// --- UI Helpers ---
function createExpandableItem(titleText, contentHtml) {
  const li = document.createElement('li');
  
  const header = document.createElement('div');
  header.className = 'item-header';
  header.innerHTML = `<span>${titleText}</span> <span>+</span>`;
  
  const details = document.createElement('div');
  details.className = 'item-details hidden';
  details.innerHTML = contentHtml;
  
  header.addEventListener('click', () => {
    details.classList.toggle('hidden');
    const span = header.querySelectorAll('span')[1];
    span.innerText = details.classList.contains('hidden') ? '+' : '-';
  });
  
  li.appendChild(header);
  li.appendChild(details);
  return li;
}

// --- Notes Logic ---
saveNoteBtn.addEventListener('click', async () => {
  const title = noteTitle.value;
  const text = noteContent.value;
  
  if (!title || !text) return showToast("Título e conteúdo são obrigatórios", "error");
  
  const payload = await encryptPayload({ title, text });
  const res = await fetchApi('/vault/notes/', { method: 'POST', body: JSON.stringify(payload) });
  
  if (res.ok) {
    showToast("Nota salva de forma segura!", "success");
    noteTitle.value = "";
    noteContent.value = "";
    loadNotesBtn.click(); // auto reload
  } else {
    showToast("Erro ao salvar nota", "error");
  }
});

loadNotesBtn.addEventListener('click', async () => {
  const res = await fetchApi('/vault/notes/');
  if (!res.ok) return showToast("Erro ao buscar notas", "error");
  const notes = await res.json();
  
  notesList.innerHTML = "";
  if(notes.length === 0) {
    notesList.innerHTML = "<p>Nenhuma nota encontrada.</p>";
    return;
  }
  
  for (const n of notes) {
    const dec = await decryptPayload(n.ciphertext, n.iv);
    
    if (dec.error) {
      const li = createExpandableItem("Erro de Descriptografia", dec.error);
      notesList.appendChild(li);
    } else {
      // Fallback para notas antigas sem titulo
      const t = dec.title || "Nota Sem Título";
      const li = createExpandableItem(t, dec.text);
      notesList.appendChild(li);
    }
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
  if (!obj.title || !obj.pass) return showToast("Título e Senha são obrigatórios", "error");
  
  const payload = await encryptPayload(obj);
  const res = await fetchApi('/vault/passwords/', { method: 'POST', body: JSON.stringify(payload) });
  
  if (res.ok) {
    showToast("Senha salva e criptografada!", "success");
    pwTitle.value = pwUser.value = pwPass.value = pwUrl.value = "";
    loadPasswordsBtn.click(); // auto reload
  }
});

loadPasswordsBtn.addEventListener('click', async () => {
  const res = await fetchApi('/vault/passwords/');
  if (!res.ok) return showToast("Erro ao buscar senhas", "error");
  const pws = await res.json();
  
  passwordsList.innerHTML = "";
  if(pws.length === 0) {
    passwordsList.innerHTML = "<p>Nenhuma senha encontrada.</p>";
    return;
  }
  
  for (const p of pws) {
    const dec = await decryptPayload(p.ciphertext, p.iv);
    
    if (dec.error) {
      const li = createExpandableItem("Erro", dec.error);
      passwordsList.appendChild(li);
    } else {
      const id = `pwd-${Math.random().toString(36).substr(2, 9)}`;
      const html = `
        Usuário: <strong>${dec.user}</strong><br>
        URL: <a href="${dec.url}" target="_blank" style="color:var(--primary-color)">${dec.url}</a><br><br>
        Senha: <span id="${id}">${dec.pass}</span><br>
        <button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('${id}').innerText).then(()=>alert('Senha copiada!'))">Copiar Senha</button>
      `;
      const li = createExpandableItem(dec.title, html);
      passwordsList.appendChild(li);
      document.getElementById('btn-' + id).addEventListener('click', () => { navigator.clipboard.writeText(dec.pass); showToast('Senha copiada!', 'success'); });
    }
  }
});



// --- Files Logic ---
uploadFileBtn.addEventListener('click', async () => {
  if (fileInput.files.length === 0) return showToast("Selecione um arquivo", "error");
  
  const file = fileInput.files[0];
  if (file.size > 1024 * 1024) {
    return showToast("O arquivo não pode exceder 1MB", "error");
  }
  
  showToast("Criptografando arquivo localmente...", "success");
  
  const arrayBuffer = await file.arrayBuffer();
  
  const ivFile = window.crypto.getRandomValues(new Uint8Array(12));
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  
  const ciphertextBuf = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: ivFile },
    encryptionKey,
    arrayBuffer
  );
  
  const ivName = window.crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const encFilenameBuf = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: ivName },
    encryptionKey,
    enc.encode(file.name)
  );
  
  const encFilenameStr = bufferToBase64(ivName) + ":" + bufferToBase64(encFilenameBuf);
  
  const formData = new FormData();
  formData.append("file", new Blob([ciphertextBuf]), "encrypted_blob");
  formData.append("encrypted_filename", encFilenameStr);
  formData.append("iv", bufferToBase64(ivFile));
  formData.append("salt", bufferToBase64(salt));
  
  const res = await fetch('http://localhost:8000/api/vault/files/upload/', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${jwtToken}` },
    body: formData
  });
  
  if (res.ok) {
    showToast("Arquivo enviado com segurança!", "success");
    fileInput.value = "";
    loadFilesBtn.click();
  } else {
    const errorData = await res.json();
    showToast(errorData.detail || "Erro ao fazer upload", "error");
  }
});

loadFilesBtn.addEventListener('click', async () => {
  const res = await fetchApi('/vault/files/');
  if (!res.ok) return showToast("Erro ao buscar arquivos", "error");
  const files = await res.json();
  
  filesList.innerHTML = "";
  if(files.length === 0) {
    filesList.innerHTML = "<p>Nenhum arquivo encontrado.</p>";
    return;
  }
  
  for (const f of files) {
    let filename = "Arquivo Desconhecido";
    const parts = f.encrypted_filename.split(':');
    if (parts.length === 2) {
      try {
        const iv = base64ToBuffer(parts[0]);
        const cipher = base64ToBuffer(parts[1]);
        const decrypted = await window.crypto.subtle.decrypt(
          { name: "AES-GCM", iv: iv },
          encryptionKey,
          cipher
        );
        filename = new TextDecoder().decode(decrypted);
      } catch (e) {
        filename = "Erro ao descriptografar nome";
      }
    }
    
    const id = `file-${f.file_id}`;
    const html = `
      <p>Salvo em: ${new Date(f.created_at).toLocaleString()}</p>
      <button class="secondary-btn" id="${id}" style="margin-top: 10px;">Decifrar e Baixar Localmente</button>
    `;
    const li = createExpandableItem(filename, html);
    filesList.appendChild(li);
    
    document.getElementById(id).addEventListener('click', async () => {
      showToast("Baixando blob criptografado...", "success");
      const dRes = await fetch(`http://localhost:8000/api/vault/files/download/${f.file_id}`, {
        headers: { 'Authorization': `Bearer ${jwtToken}` }
      });
      
      if (!dRes.ok) return showToast("Erro no download", "error");
      
      const encBlob = await dRes.blob();
      const encBuffer = await encBlob.arrayBuffer();
      const ivBuffer = base64ToBuffer(f.iv);
      
      try {
        const decBuffer = await window.crypto.subtle.decrypt(
          { name: "AES-GCM", iv: ivBuffer },
          encryptionKey,
          encBuffer
        );
        
        const decBlob = new Blob([decBuffer], { type: "application/octet-stream" });
        const url = URL.createObjectURL(decBlob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        
        showToast("Download completo!", "success");
      } catch (e) {
        showToast("Erro ao decifrar o arquivo. Chave incorreta?", "error");
      }
    });
  }
});
