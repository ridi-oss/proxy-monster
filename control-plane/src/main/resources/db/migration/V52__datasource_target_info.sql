-- Where the proxy connects, as its engine describes it, in place of a host and port only some engines have.
ALTER TABLE datasource ADD COLUMN target_info TEXT NOT NULL DEFAULT '';
UPDATE datasource SET target_info = host || ':' || port WHERE host <> '';
ALTER TABLE datasource DROP COLUMN host, DROP COLUMN port;
