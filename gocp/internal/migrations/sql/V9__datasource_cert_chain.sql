-- One trust mechanism for the wire, replacing two.
--
-- The proxy advertises the certificate CHAIN a client should trust: its leaf, any intermediates, and the
-- root. Self-signed is the one-element case and needs no special handling. Every client then does ordinary
-- TLS verification against that chain -- pmon uses it as its root pool, and psql/mysql/DataGrip take the
-- same bytes as sslrootcert / --ssl-ca with verify-full.
--
-- advertise_cert_sha256 goes away. It pinned the leaf by digest, which required turning OFF the usual CA
-- and hostname checks to work -- so a stolen leaf replayed on another host passed the pin. Verifying
-- against the chain with the server name checked is strictly stronger, and it is the same verification
-- every other TLS client already performs. Holding both also meant two values describing one certificate,
-- which could disagree.
ALTER TABLE datasource DROP CONSTRAINT IF EXISTS datasource_advertise_cert_sha256_check;
ALTER TABLE datasource DROP COLUMN IF EXISTS advertise_cert_sha256;

-- PEM, leaf first (the order TLS itself uses). NULL until a proxy with wire TLS advertises one. Whether a
-- chain is usable is the client's verification to make, so an odd one is stored and served with a warning
-- rather than refused -- rejecting at registration would mean no datasource, no catalog, and every decision
-- failing closed. Not secret: these are the certificates the proxy already presents to every client that
-- opens a TLS connection to it. The private key never leaves the proxy.
ALTER TABLE datasource ADD COLUMN advertise_cert_chain TEXT;

-- Whether the proxy serves client-facing TLS at all -- a SEPARATE fact from the chain above, not derivable
-- from it. An operator may serve a publicly-trusted certificate and publish no chain (PM_TLS_NO_ADVERTISE),
-- and a transient cert read at re-register also publishes none. A client needs the requirement to know that
-- a plaintext greeting must be refused instead of being handed a session token in the clear.
--
-- Defaults false so a row that predates any registration is treated as plaintext until a proxy says
-- otherwise: the safe direction is to withhold trust, never to assume it.
ALTER TABLE datasource ADD COLUMN advertise_wire_tls BOOLEAN NOT NULL DEFAULT FALSE;
