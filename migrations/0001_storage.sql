CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    data TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS members (
    project TEXT NOT NULL REFERENCES projects(id),
    user TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'reviewer', 'viewer')),
    PRIMARY KEY (project, user)
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    project TEXT NOT NULL REFERENCES projects(id),
    requester TEXT NOT NULL,
    request_id TEXT NOT NULL,
    fixture TEXT NOT NULL,
    status TEXT NOT NULL,
    data TEXT NOT NULL,
    UNIQUE (project, requester, request_id)
);

CREATE INDEX IF NOT EXISTS scans_by_project ON scans(project);

CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY,
    scan TEXT NOT NULL REFERENCES scans(id),
    data TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS reviews_by_scan ON reviews(scan);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY,
    project TEXT NOT NULL REFERENCES projects(id),
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    subject TEXT NOT NULL,
    recorded_at INTEGER NOT NULL DEFAULT (unixepoch())
);
