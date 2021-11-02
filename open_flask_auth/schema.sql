DROP TABLE IF EXISTS enrollments;
DROP TABLE IF EXISTS revocations;

CREATE TABLE enrollments (
    user_id INTEGER PRIMARY KEY,
    public_key TEXT NOT NULL,
    secret_hash TEXT NOT NULL
);

CREATE TABLE revocations (
    token_id TEXT PRIMARY KEY,
    revoked_on TIMESTAMP NOT NULL
);
