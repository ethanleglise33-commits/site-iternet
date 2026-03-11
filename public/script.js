const API_BASE = '/api';

let supabaseClient = null;
let currentSession = null;
let currentUser = null;
let realtimeChannel = null;
let switchAuthTab = null;

const authScreen = document.getElementById('auth-screen');
const appScreen = document.getElementById('app-screen');
const messagesContainer = document.getElementById('messages-container');
const messageForm = document.getElementById('message-form');
const messageInput = document.getElementById('message');
const formError = document.getElementById('form-error');
const sidebarAvatar = document.getElementById('sidebar-avatar');
const sidebarUsername = document.getElementById('sidebar-username');

async function init() {
  createStars();
  setupTabs();
  setupAuthForms();
  setupMessageForm();
  setupLogout();

  try {
    const res = await fetch(`${API_BASE}/config`);
    if (!res.ok) throw new Error('Config serveur indisponible.');

    const { supabaseUrl, supabaseAnonKey } = await res.json();
    supabaseClient = window.supabase.createClient(supabaseUrl, supabaseAnonKey);

    supabaseClient.auth.onAuthStateChange(async (_event, session) => {
      currentSession = session;
      currentUser = session?.user || null;

      if (currentUser) {
        showApp();
        await bootstrapChatSafe();
      } else {
        showAuth();
        unsubscribeRealtime();
      }
    });

    const { data } = await supabaseClient.auth.getSession();
    currentSession = data.session;
    currentUser = data.session?.user || null;

    if (currentUser) {
      showApp();
      await bootstrapChatSafe();
    } else {
      showAuth();
    }
  } catch (err) {
    showGlobalAuthError(err.message || 'Erreur initialisation.');
    showAuth();
  }
}

function setupTabs() {
  const tabButtons = document.querySelectorAll('.tab-btn');
  const loginForm = document.getElementById('login-form');
  const registerForm = document.getElementById('register-form');
  const loginError = document.getElementById('login-error');
  const registerError = document.getElementById('register-error');

  function switchTab(tab) {
    tabButtons.forEach((b) => b.classList.toggle('active', b.dataset.tab === tab));
    loginForm.classList.toggle('active', tab === 'login');
    registerForm.classList.toggle('active', tab === 'register');
    loginError.hidden = true;
    registerError.hidden = true;
  }

  switchAuthTab = switchTab;
  switchTab('login');

  tabButtons.forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      switchTab(btn.dataset.tab);
    });
  });
}

function setupAuthForms() {
  const loginForm = document.getElementById('login-form');
  const registerForm = document.getElementById('register-form');

  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const email = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-password').value;
    const errBox = document.getElementById('login-error');
    const button = document.getElementById('login-btn');

    errBox.hidden = true;
    resetAuthNoticeStyle(errBox);
    toggleLoading(button, true, 'Connexion...');

    try {
      const { data, error } = await supabaseClient.auth.signInWithPassword({ email, password });
      if (error) throw error;

      if (!data?.session) {
        throw new Error('Session introuvable après connexion.');
      }

      currentSession = data.session;
      currentUser = data.user;

      showApp();
      await bootstrapChatSafe();
      loginForm.reset();
    } catch (err) {
      showAuth();
      errBox.textContent = normalizeSupabaseError(err.message);
      errBox.hidden = false;
    } finally {
      toggleLoading(button, false);
    }
  });

  registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('reg-username').value.trim();
    const email = document.getElementById('reg-email').value.trim();
    const password = document.getElementById('reg-password').value;
    const errBox = document.getElementById('register-error');
    const button = document.getElementById('register-btn');

    errBox.hidden = true;
    resetAuthNoticeStyle(errBox);
    toggleLoading(button, true, 'Creation...');

    try {
      const { error } = await supabaseClient.auth.signUp({
        email,
        password,
        options: { data: { username } },
      });
      if (error) throw error;

      registerForm.reset();
      if (typeof switchAuthTab === 'function') switchAuthTab('login');

      const loginEmailInput = document.getElementById('login-email');
      const loginError = document.getElementById('login-error');
      loginEmailInput.value = email;
      loginError.textContent = 'Compte cree. Connecte-toi maintenant.';
      loginError.style.color = '#c0ffe7';
      loginError.style.background = 'rgba(87, 242, 179, 0.14)';
      loginError.style.borderColor = 'rgba(87, 242, 179, 0.4)';
      loginError.hidden = false;
    } catch (err) {
      errBox.textContent = normalizeSupabaseError(err.message);
      errBox.hidden = false;
    } finally {
      toggleLoading(button, false);
    }
  });
}

function setupMessageForm() {
  messageForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    await sendMessage();
  });

  messageInput.addEventListener('keydown', async (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      await sendMessage();
    }
  });

  messageInput.addEventListener('input', autoResizeMessageInput);
}

function setupLogout() {
  document.getElementById('logout-btn').addEventListener('click', async () => {
    try {
      await supabaseClient.auth.signOut();
    } catch (err) {
      alert(err.message);
    }
  });
}

async function bootstrapChatSafe() {
  try {
    await refreshCurrentUserProfile();
  } catch {
    sidebarUsername.textContent = currentUser?.email || 'Utilisateur';
    sidebarAvatar.style.background = '#4a6bff';
  }

  try {
    await loadMessages();
  } catch {
    messagesContainer.innerHTML = '<div class="error-msg">Impossible de charger les messages.</div>';
  }

  subscribeRealtime();
}

async function sendMessage() {
  if (!currentSession?.access_token) return;

  const text = messageInput.value.trim();
  if (!text) return;

  formError.hidden = true;

  try {
    const res = await fetch(`${API_BASE}/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${currentSession.access_token}`,
      },
      body: JSON.stringify({ text }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Erreur envoi message.');

    messageInput.value = '';
    autoResizeMessageInput();
    await loadMessages();
  } catch (err) {
    formError.textContent = err.message;
    formError.hidden = false;
  }
}

async function loadMessages() {
  const res = await fetch(`${API_BASE}/messages`);
  if (!res.ok) throw new Error('Impossible de charger les messages.');
  const messages = await res.json();

  if (!messages.length) {
    messagesContainer.innerHTML = '<div class="empty-state">Aucun message. Lance la premiere discussion.</div>';
    return;
  }

  messagesContainer.innerHTML = messages.map((msg) => renderMessageCard(msg)).join('');
  messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function renderMessageCard(msg) {
  const profile = normalizeProfile(msg.profiles);
  const username = profile?.username || 'Utilisateur';
  const avatarColor = profile?.avatar_color || '#4a6bff';
  const mine = currentUser && msg.user_id === currentUser.id;

  return `
    <article class="message-card" data-id="${escapeAttr(msg.id)}">
      <div class="message-avatar" style="background:${escapeAttr(avatarColor)}"></div>
      <div class="message-main">
        <div class="message-meta">
          <span class="message-author">${escapeHtml(username)}</span>
          <span class="message-date">${formatDate(msg.created_at)}</span>
        </div>
        <p class="message-text">${escapeHtml(msg.text)}</p>
      </div>
      ${mine ? `<button class="delete-btn" onclick="deleteMessage('${escapeAttr(msg.id)}')" title="Supprimer">Suppr.</button>` : ''}
    </article>
  `;
}

async function deleteMessage(id) {
  if (!currentSession?.access_token) return;
  if (!confirm('Supprimer ce message ?')) return;

  try {
    const res = await fetch(`${API_BASE}/messages/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${currentSession.access_token}` },
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Suppression impossible.');

    await loadMessages();
  } catch (err) {
    alert(err.message);
  }
}

window.deleteMessage = deleteMessage;

async function refreshCurrentUserProfile() {
  const { data, error } = await supabaseClient
    .from('profiles')
    .select('username, avatar_color')
    .eq('id', currentUser.id)
    .single();

  if (error) throw error;

  sidebarUsername.textContent = data.username;
  sidebarAvatar.style.background = data.avatar_color || '#4a6bff';
}

function subscribeRealtime() {
  if (realtimeChannel || !supabaseClient) return;

  realtimeChannel = supabaseClient
    .channel('messages-live-room')
    .on('postgres_changes', { event: '*', schema: 'public', table: 'messages' }, () => {
      loadMessages().catch(() => {});
    })
    .subscribe();
}

function unsubscribeRealtime() {
  if (!realtimeChannel || !supabaseClient) return;
  supabaseClient.removeChannel(realtimeChannel);
  realtimeChannel = null;
}

function showAuth() {
  authScreen.hidden = false;
  appScreen.hidden = true;
}

function showApp() {
  authScreen.hidden = true;
  appScreen.hidden = false;
}

function showGlobalAuthError(message) {
  const box = document.getElementById('login-error');
  box.textContent = message;
  box.hidden = false;
}

function autoResizeMessageInput() {
  messageInput.style.height = 'auto';
  messageInput.style.height = `${Math.min(messageInput.scrollHeight, 220)}px`;
}

function toggleLoading(button, loading, loadingText = 'Chargement...') {
  const textNode = button.querySelector('.btn-text');
  const loaderNode = button.querySelector('.btn-loader');
  button.disabled = loading;
  textNode.hidden = loading;
  loaderNode.hidden = !loading;
  if (loading) loaderNode.textContent = loadingText;
}

function normalizeProfile(profileValue) {
  if (!profileValue) return null;
  if (Array.isArray(profileValue)) return profileValue[0] || null;
  return profileValue;
}

function normalizeSupabaseError(message = '') {
  if (message.includes('Invalid login credentials')) return 'Identifiants invalides.';
  if (message.includes('User already registered')) return 'Cet email existe deja.';
  if (message.includes('Password should be at least')) return 'Mot de passe trop court.';
  if (message.includes('Email not confirmed')) return 'Email non confirme (desactive Confirm email dans Supabase Auth).';
  return message || 'Une erreur est survenue.';
}

function formatDate(value) {
  return new Date(value).toLocaleString('fr-FR', {
    day: '2-digit',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = String(str);
  return div.innerHTML;
}

function escapeAttr(str) {
  return String(str).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function createStars() {
  const starsContainer = document.getElementById('stars');
  if (!starsContainer) return;

  const count = Math.min(110, Math.floor(window.innerWidth / 10));
  for (let i = 0; i < count; i += 1) {
    const star = document.createElement('span');
    star.className = 'star';
    star.style.left = `${Math.random() * 100}%`;
    star.style.top = `${Math.random() * 100}%`;
    star.style.setProperty('--dur', `${2 + Math.random() * 4}s`);
    star.style.setProperty('--delay', `${Math.random() * 3}s`);
    starsContainer.appendChild(star);
  }
}

function resetAuthNoticeStyle(element) {
  element.style.color = '';
  element.style.background = '';
  element.style.borderColor = '';
}

init();
