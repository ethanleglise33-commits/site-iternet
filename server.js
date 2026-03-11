require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.SUPABASE_URL || !process.env.SUPABASE_ANON_KEY) {
  console.error('❌ SUPABASE_URL et SUPABASE_ANON_KEY sont requis. Vérifie tes variables d\'environnement.');
  process.exit(1);
}

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// GET tous les messages
app.get('/api/messages', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('messages')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST un nouveau message
app.post('/api/messages', async (req, res) => {
  try {
    const { text, author } = req.body;

    if (!text || text.trim() === '') {
      return res.status(400).json({ error: 'Le message ne peut pas être vide.' });
    }

    const sanitizedText = text.trim().slice(0, 1000);
    const sanitizedAuthor = (author?.trim() || 'Anonyme').slice(0, 100);

    const { data, error } = await supabase
      .from('messages')
      .insert([{ text: sanitizedText, author: sanitizedAuthor }])
      .select();

    if (error) throw error;
    res.status(201).json(data[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE un message
app.delete('/api/messages/:id', async (req, res) => {
  try {
    const { id } = req.params;

    // Valider le format UUID pour éviter les injections
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(id)) {
      return res.status(400).json({ error: 'ID invalide.' });
    }

    const { error } = await supabase
      .from('messages')
      .delete()
      .eq('id', id);

    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Serveur démarré sur le port ${PORT}`);
});
