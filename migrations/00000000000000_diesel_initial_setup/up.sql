-- Your SQL goes here
CREATE TABLE users (
    id INTEGER PRIMARY KEY NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    username VARCHAR NOT NULL,
    email VARCHAR NOT NULL,
    password VARCHAR NOT NULL,
    login_session VARCHAR NOT NULL DEFAULT ''
);


CREATE TRIGGER IF NOT EXISTS UpdateTimestamps AFTER UPDATE ON users
  FOR EACH ROW WHEN NEW.updated_at <= OLD.updated_at
BEGIN
  update users set updated_at=CURRENT_TIMESTAMP where id=OLD.id;
END;
