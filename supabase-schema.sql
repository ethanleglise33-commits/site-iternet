-- Colle ce SQL dans l'éditeur SQL de ton projet Supabase
-- (Dashboard → SQL Editor → New query)

-- 1. Créer la table messages
CREATE TABLE IF NOT EXISTS messages (
  id         UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
  text       TEXT        NOT NULL,
  author     TEXT        NOT NULL DEFAULT 'Anonyme',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Activer Row Level Security
ALTER TABLE messages ENABLE ROW LEVEL SECURITY;

-- 3. Politiques d'accès public (lecture, écriture, suppression)
CREATE POLICY "Lecture publique"     ON messages FOR SELECT USING (true);
CREATE POLICY "Insertion publique"   ON messages FOR INSERT WITH CHECK (true);
CREATE POLICY "Suppression publique" ON messages FOR DELETE USING (true);
