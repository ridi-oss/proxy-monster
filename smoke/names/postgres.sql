-- A quoted mixed-case table beside its unquoted lowercase namesake.
CREATE TABLE "Customers" (id BIGINT PRIMARY KEY, "Email" VARCHAR(64), "Phone" VARCHAR(64), "Ssn" VARCHAR(64), "Secret" VARCHAR(64));
INSERT INTO "Customers" VALUES
    (1, 'upper-email-1', 'upper-phone-1', 'upper-ssn-1', 'upper-secret-1'),
    (2, 'upper-email-2', 'upper-phone-2', 'upper-ssn-2', 'upper-secret-2'),
    (3, 'upper-email-3', 'upper-phone-3', 'upper-ssn-3', 'upper-secret-3');

CREATE TABLE customers (id BIGINT PRIMARY KEY, email VARCHAR(64), phone VARCHAR(64), ssn VARCHAR(64), secret VARCHAR(64));
INSERT INTO customers VALUES
    (1, 'lower-email-1', 'lower-phone-1', 'lower-ssn-1', 'lower-secret-1'),
    (2, 'lower-email-2', 'lower-phone-2', 'lower-ssn-2', 'lower-secret-2'),
    (3, 'lower-email-3', 'lower-phone-3', 'lower-ssn-3', 'lower-secret-3');
