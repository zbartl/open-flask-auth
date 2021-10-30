DROP TABLE IF EXISTS enrollments;

CREATE TABLE enrollments (
    user_id INTEGER PRIMARY KEY,
    public_key TEXT NOT NULL,
    secret_hash TEXT NOT NULL
);