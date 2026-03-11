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
        await refreshCurrentUserProfile();
        await loadMessages();
        subscribeRealtime();
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
      await refreshCurrentUserProfile();
      await loadMessages();
      subscribeRealtime();
    } else {
      showAuth();
    }
  } catch (err) {
    showGlobalAuthError(err.message);
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

  // Etat initial: connexion visible uniquement
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
    toggleLoading(button, true, 'Connexion...');

    try {

      // MODIFICATION ICI
      const { data, error } = await supabaseClient.auth.signInWithPassword({
        email,
        password
      });

      if (error) throw error;

      if (data?.session) {
        currentSession = data.session;
        currentUser = data.user;
        showApp();
        await refreshCurrentUserProfile();
        await loadMessages();
        subscribeRealtime();
      }

      loginForm.reset();

    } catch (err) {
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
    toggleLoading(button, true, 'Creation...');

    try {
      const { error } = await supabaseClient.auth.signUp({
        email,
        password,
        options: {
          data: {
            username,
          },
        },
      });
      if (error) throw error;
      registerForm.reset();

      // Basculer automatiquement vers la connexion après inscription réussie.
      if (typeof switchAuthTab === 'function') {
        switchAuthTab('login');
      }

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