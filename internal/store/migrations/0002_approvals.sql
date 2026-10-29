-- Approval decisions, kept apart from services so reconciler writes to the
-- services table can never clobber them. fingerprint binds the approval to the
-- approved service content. approved_at is UTC unix seconds.
CREATE TABLE approvals (
    key         TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    approved_at INTEGER NOT NULL
);
