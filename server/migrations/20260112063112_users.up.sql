-- Add up migration script here

CREATE TYPE user_group AS ENUM ('admin', 'user');
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE "users" (
  id UUID NOT NULL PRIMARY KEY DEFAULT (uuid_generate_v4()),
  username VARCHAR(100) NOT NULL UNIQUE,
  verified BOOLEAN NOT NULL DEFAULT FALSE,
  password VARCHAR(255) NOT NULL,
  group1 user_group NOT NULL DEFAULT 'user',
  created TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX users_username_idx ON users (username);
