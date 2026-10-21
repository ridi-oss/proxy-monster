-- Under lower_case_table_names=1 the server stores this table as `customers`.
USE acme;

CREATE TABLE Customers (id BIGINT PRIMARY KEY, Email VARCHAR(64), Phone VARCHAR(64), Ssn VARCHAR(64), Secret VARCHAR(64));
INSERT INTO Customers VALUES
    (1, 'upper-email-1', 'upper-phone-1', 'upper-ssn-1', 'upper-secret-1'),
    (2, 'upper-email-2', 'upper-phone-2', 'upper-ssn-2', 'upper-secret-2'),
    (3, 'upper-email-3', 'upper-phone-3', 'upper-ssn-3', 'upper-secret-3');
