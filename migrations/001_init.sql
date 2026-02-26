-- Initial schema for megapark
CREATE TABLE IF NOT EXISTS halls (
  id text PRIMARY KEY,
  name text NOT NULL,
  description text,
  capacity integer DEFAULT 0,
  price_per_day numeric DEFAULT 0,
  amenities text[],
  images text[],
  availability boolean DEFAULT true,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rooms (
  id text PRIMARY KEY,
  room_number text,
  name text,
  type text,
  description text,
  price_per_night numeric DEFAULT 0,
  capacity integer DEFAULT 1,
  amenities text[],
  images text[],
  availability boolean DEFAULT true,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS bookings (
  id text PRIMARY KEY,
  type text,
  payload jsonb,
  total_price numeric DEFAULT 0,
  status text DEFAULT 'pending',
  payment_status text DEFAULT 'pending',
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS menu_items (
  id text PRIMARY KEY,
  name text NOT NULL,
  description text,
  category text,
  price numeric DEFAULT 0,
  preparation_time integer DEFAULT 0,
  image text,
  availability boolean DEFAULT true,
  created_at timestamptz DEFAULT now()
);

-- Users table for customers and staff
CREATE TABLE IF NOT EXISTS users (
  id text PRIMARY KEY,
  email text UNIQUE NOT NULL,
  password_hash text NOT NULL,
  name text,
  phone text,
  role text DEFAULT 'customer',
  is_active boolean DEFAULT true,
  created_at timestamptz DEFAULT now()
);
