-- A quarantined route is kept (its key keeps the hostname, its DNS records
-- and certificates stay) but is not rendered: an approve-mode service whose
-- approved content changed is not served until it is re-approved. The next
-- route write (a Published service) clears it.
ALTER TABLE routes ADD COLUMN quarantined INTEGER NOT NULL DEFAULT 0;
