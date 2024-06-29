-- Create users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create index on username for quick lookup during login
CREATE INDEX idx_users_username ON users (username);

-- Create index on email to ensure uniqueness
CREATE INDEX idx_users_email ON users (email);