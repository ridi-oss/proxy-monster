-- An edit of a request's SQL bumps revision; an approval must name the revision it approves.
ALTER TABLE access_request ADD COLUMN revision INT NOT NULL DEFAULT 1;
ALTER TABLE access_request ADD COLUMN revised_at TIMESTAMPTZ;
