require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const path    = require('path');
const { createClient } = require('@supabase/supabase-js');

const app  = express();
const PORT = process.env.PORT || 3000;

if (!process.env.SUPABASE_URL || !process.env.SUPABASE_ANON_KEY) {
  console.error('❌ SUPABASE_URL et SUPABASE_ANON_KEY sont requis.');
  process.exit(1);
}

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'), {
  etag: false,
  lastModified: false,
  setHeaders: (res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  },
}));

app.get('/api/health', (req, res) => {
  res.json({ ok: true, version: 'chatspace-auth-v2' });
});

// ── Middleware auth ────────────────────────────────────────────────────────
async function authenticateUser(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Non authentifié.' });
  }
  const token = authHeader.slice(7);
  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user) {
    return res.status(401).json({ error: 'Token invalide ou expiré.' });
  }
  req.user  = user;
  req.token = token;
  next();
}

// ── Auth backend (évite les blocages navigateur -> Supabase) ───────────────
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email et mot de passe requis.' });
    }

    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) throw error;
    if (!data?.session || !data?.user) {
      return res.status(401).json({ error: 'Connexion impossible.' });
    }

    res.json({
      user: data.user,
      session: {
        access_token: data.session.access_token,
        refresh_token: data.session.refresh_token,
        expires_at: data.session.expires_at,
      },
    });
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, username } = req.body;
    if (!email || !password || !username) {
      return res.status(400).json({ error: 'Email, mot de passe et username requis.' });
    }

    const safeUsername = String(username).trim().slice(0, 30);
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: { data: { username: safeUsername } },
    });
    if (error) throw error;

    res.status(201).json({
      message: 'Compte créé. Connecte-toi maintenant.',
      user: data.user || null,
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/auth/me', authenticateUser, async (req, res) => {
  res.json({ user: req.user });
});

app.get('/api/profile', authenticateUser, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('profiles')
      .select('username, avatar_color')
      .eq('id', req.user.id)
      .single();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET messages (public) ──────────────────────────────────────────────────
app.get('/api/messages', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('messages')
      .select('*, profiles(username, avatar_color)')
      .order('created_at', { ascending: true })
      .limit(200);
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST message (auth requis) ─────────────────────────────────────────────
app.post('/api/messages', authenticateUser, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text || text.trim() === '') {
      return res.status(400).json({ error: 'Le message ne peut pas être vide.' });
    }
    const sanitizedText = text.trim().slice(0, 1000);

    // Client avec le JWT de l'utilisateur → RLS s'applique avec son identité
    const userClient = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_ANON_KEY,
      { global: { headers: { Authorization: `Bearer ${req.token}` } } }
    );
    const { data, error } = await userClient
      .from('messages')
      .insert([{ text: sanitizedText, user_id: req.user.id }])
      .select('*, profiles(username, avatar_color)');
    if (error) throw error;
    res.status(201).json(data[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE message (auth + propriétaire uniquement) ────────────────────────
app.delete('/api/messages/:id', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(id)) {
      return res.status(400).json({ error: 'ID invalide.' });
    }

    // Vérification propriété
    const { data: msg } = await supabase
      .from('messages').select('user_id').eq('id', id).single();
    if (!msg || msg.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Non autorisé.' });
    }

    const userClient = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_ANON_KEY,
      { global: { headers: { Authorization: `Bearer ${req.token}` } } }
    );
    const { error } = await userClient.from('messages').delete().eq('id', id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Serveur démarré sur le port ${PORT}`);
});