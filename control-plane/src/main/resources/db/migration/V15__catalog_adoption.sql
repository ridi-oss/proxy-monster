-- How a new connection to a datasource obtains its catalog.
--
-- 'verify' makes the connection measure each schema's hash against its own backend and adopt the held
-- content only when the two agree. 'trust' adopts what the control plane holds with no probe at all,
-- which is sound while every backend session for the datasource reaches one server under one account.
--
-- NULL is the default and derives the mode from the engine, so an operator who has said nothing gets
-- the behavior their engine makes safe. An explicit value always wins, on any engine: the setting is
-- the operator's assertion about their own topology, which no engine-level predicate can second-guess.

ALTER TABLE datasource ADD COLUMN catalog_adoption TEXT;

ALTER TABLE datasource ADD CONSTRAINT datasource_catalog_adoption_check
    CHECK (catalog_adoption IS NULL OR catalog_adoption IN ('verify', 'trust'));
