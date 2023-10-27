-- Create "users" table
CREATE TABLE IF NOT EXISTS "users" (
     "id" BIGSERIAL PRIMARY KEY,
     "email" text NOT NULL UNIQUE
);

-- Create "user_sessions" table
CREATE TABLE IF NOT EXISTS "user_sessions" (
     "id" SERIAL PRIMARY KEY,
     "user_id" bigint NOT NULL,
     "session_token_p1" text NOT NULL,
     "session_token_p2" text NOT NULL,
     "created_at" bigint NOT NULL,
     "expires_at" bigint NOT NULL
);

-- Create "oauth2_state_storage" table
CREATE TABLE IF NOT EXISTS "oauth2_state_storage" (
    "id" SERIAL PRIMARY KEY,
    "csrf_state" text NOT NULL,
    "pkce_code_verifier" text NOT NULL,
    "return_url" text NOT NULL
);
