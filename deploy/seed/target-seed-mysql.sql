-- Sample OLTP schema for the target (brokered) MySQL backend —
-- MySQL is the primary target engine (Postgres is the add-on). Mirrors
-- deploy/seed/target-seed.sql so the same queries exercise the engine + enforcement
-- on MySQL. PII columns (email, phone, name, ssn, card_number, line1,
-- postal_code) are the masking/deny targets; audit_log.payload is the
-- free-text column the content backstop covers. DATETIME (not TIMESTAMP) to
-- avoid TZ conversion + the 2038 range limit.

-- The proxy brokers to the backend with a native-password handshake (8.4 has it disabled by
-- default; the container is started with --mysql-native-password=ON). caching_sha2 is a follow-up.
ALTER USER 'acme'@'%' IDENTIFIED WITH mysql_native_password BY 'acme';

USE acme;

CREATE TABLE users (
    id         BIGINT PRIMARY KEY,
    email      VARCHAR(255),  -- PII
    phone      VARCHAR(255),  -- PII
    name       VARCHAR(255),  -- PII
    ssn        VARCHAR(255),  -- PII: resident registration no. (KR national id)
    region     VARCHAR(255),
    created_at DATETIME
);

CREATE TABLE orders (
    id         BIGINT PRIMARY KEY,
    user_id    BIGINT,
    book_id    BIGINT,
    amount     DECIMAL(19, 4),
    status     VARCHAR(255),
    created_at DATETIME
);

CREATE TABLE payments (
    id          BIGINT PRIMARY KEY,
    order_id    BIGINT,
    card_number VARCHAR(255),  -- PII
    card_last4  VARCHAR(255),
    amount      DECIMAL(19, 4),
    paid_at     DATETIME
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
    at      DATETIME
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
    (1, 'system',     'user.login',    'ip=10.0.0.5; ua=mysql',                     '2025-04-01 09:59:00'),
    (2, 'admin@example.com', 'order.refund',  'order=102; reason=customer requested',      '2025-04-05 15:11:00');
