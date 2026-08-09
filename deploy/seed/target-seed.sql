-- Sample OLTP schema for the target (brokered) Postgres backend.
-- Mirrors the catalog the analyzer's parse+lineage tests use, so the same queries run
-- against a real database here.
-- PII columns (email, phone, name, ssn, card_number, line1, postal_code) are what the
-- column policy / masking engine will target; audit_log.payload is the free-text column
-- the content backstop covers.

CREATE TABLE users (
    id         BIGINT PRIMARY KEY,
    email      VARCHAR(255),  -- PII
    phone      VARCHAR(255),  -- PII
    name       VARCHAR(255),  -- PII
    ssn        VARCHAR(255),  -- PII: resident registration no. (KR national id)
    region     VARCHAR(255),
    created_at TIMESTAMP
);

CREATE TABLE orders (
    id         BIGINT PRIMARY KEY,
    user_id    BIGINT,
    book_id    BIGINT,
    amount     DECIMAL(19, 4),
    status     VARCHAR(255),
    created_at TIMESTAMP
);

CREATE TABLE payments (
    id          BIGINT PRIMARY KEY,
    order_id    BIGINT,
    card_number VARCHAR(255),  -- PII
    card_last4  VARCHAR(255),
    amount      DECIMAL(19, 4),
    paid_at     TIMESTAMP
);

CREATE TABLE addresses (
    id          BIGINT PRIMARY KEY,
    user_id     BIGINT,
    line1       VARCHAR(255),  -- PII
    city        VARCHAR(255),
    postal_code VARCHAR(255)   -- PII
);

CREATE TABLE books (
    id     BIGINT PRIMARY KEY,
    title  VARCHAR(255),
    author VARCHAR(255),
    price  DECIMAL(19, 4)
);

CREATE TABLE audit_log (
    id      BIGINT PRIMARY KEY,
    actor   VARCHAR(255),
    action  VARCHAR(255),
    payload VARCHAR(255),  -- free-text / JSON: the content-backstop target
    at      TIMESTAMP
);

INSERT INTO users (id, email, phone, name, ssn, region, created_at) VALUES
    (1, 'jiwon@example.com',  '010-1111-2222', 'Kim Jiwon',  '987-65-4320', 'KR-11', '2025-01-02 09:00:00'),
    (2, 'minseo@example.com', '010-3333-4444', 'Lee Minseo', '987-65-4322', 'KR-26', '2025-02-14 13:30:00'),
    (3, 'haeun@example.com',  '010-5555-6666', 'Park Haeun', '987-65-4323', 'KR-41', '2025-03-21 18:45:00');

INSERT INTO books (id, title, author, price) VALUES
    (10, 'The Vegetarian',        'Han Kang',     12000.00),
    (11, 'Pachinko',              'Min Jin Lee',  15800.00),
    (12, 'Kim Jiyoung, Born 1982','Cho Nam-joo',   9900.00);

INSERT INTO orders (id, user_id, book_id, amount, status, created_at) VALUES
    (100, 1, 10, 12000.00, 'PAID',     '2025-04-01 10:00:00'),
    (101, 2, 11, 15800.00, 'PAID',     '2025-04-03 11:20:00'),
    (102, 3, 12,  9900.00, 'CANCELED', '2025-04-05 15:10:00');

INSERT INTO payments (id, order_id, card_number, card_last4, amount, paid_at) VALUES
    (1000, 100, '4111111111111111', '1111', 12000.00, '2025-04-01 10:00:05'),
    (1001, 101, '5500005555555559', '5559', 15800.00, '2025-04-03 11:20:08');

INSERT INTO addresses (id, user_id, line1, city, postal_code) VALUES
    (1, 1, '123 Teheran-ro', 'Seoul',   '06133'),
    (2, 2, '45 Haeundae-ro', 'Busan',   '48095'),
    (3, 3, '7 Dunsan-ro',    'Daejeon', '35229');

INSERT INTO audit_log (id, actor, action, payload, at) VALUES
    (1, 'system',     'user.login',    'ip=10.0.0.5; ua=psql',                      '2025-04-01 09:59:00'),
    (2, 'admin@example.com', 'order.refund',  'order=102; reason=customer requested',      '2025-04-05 15:11:00');
