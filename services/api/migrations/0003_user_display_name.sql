-- Add optional display_name to users for the profile screen.
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS display_name TEXT;
