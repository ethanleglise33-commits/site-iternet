-- ============================================================
-- ChatSpace - Schema Supabase (auth + messages)
-- ============================================================

-- Pour simplifier les tests: Authentication > Providers > Email
-- Desactive "Confirm email" si tu veux login immediat apres inscription.

-- Nettoyage pour pouvoir rejouer le script proprement
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
DROP FUNCTION IF EXISTS public.handle_new_user();

DROP POLICY IF EXISTS "Profils publics" ON profiles;
DROP POLICY IF EXISTS "Créer son profil" ON profiles;
DROP POLICY IF EXISTS "Modifier son profil" ON profiles;

DROP POLICY IF EXISTS "Lire messages" ON messages;
DROP POLICY IF EXISTS "Envoyer message" ON messages;
DROP POLICY IF EXISTS "Supprimer son message" ON messages;

DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS profiles;

-- Profils publics relies aux comptes auth.users
CREATE TABLE profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  username TEXT UNIQUE NOT NULL CHECK (char_length(username) BETWEEN 2 AND 30),
  avatar_color TEXT NOT NULL DEFAULT '#47d3ff',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Profils publics"
ON profiles FOR SELECT
USING (true);

CREATE POLICY "Créer son profil"
ON profiles FOR INSERT
WITH CHECK (auth.uid() = id);

CREATE POLICY "Modifier son profil"
ON profiles FOR UPDATE
USING (auth.uid() = id);

-- Trigger auto: quand un user s'inscrit, on cree son profile
CREATE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
DECLARE
  random_color TEXT;
BEGIN
  random_color := '#' || lpad(to_hex(floor(random() * 16777215)::int), 6, '0');

  INSERT INTO public.profiles (id, username, avatar_color)
  VALUES (
    NEW.id,
    COALESCE(NEW.raw_user_meta_data->>'username', split_part(NEW.email, '@', 1)),
    random_color
  );

  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER on_auth_user_created
AFTER INSERT ON auth.users
FOR EACH ROW EXECUTE PROCEDURE public.handle_new_user();

-- Messages relies aux profiles
CREATE TABLE messages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  text TEXT NOT NULL CHECK (char_length(trim(text)) > 0 AND char_length(text) <= 1000),
  user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE messages ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Lire messages"
ON messages FOR SELECT
USING (true);

CREATE POLICY "Envoyer message"
ON messages FOR INSERT
WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Supprimer son message"
ON messages FOR DELETE
USING (auth.uid() = user_id);

-- Realtime
ALTER PUBLICATION supabase_realtime ADD TABLE messages;
