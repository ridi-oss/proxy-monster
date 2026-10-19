package mysql_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/ridi-oss/proxy-monster/goproxy/internal/dbtest"
	pb "github.com/ridi-oss/proxy-monster/goproxy/internal/pb"
	"github.com/ridi-oss/proxy-monster/goproxy/mysql"
	"github.com/ridi-oss/proxy-monster/goproxy/relay"
)

// diagDB holds the schema objects the allowlist cases raise errors against; diagROSchema is a READ ONLY
// schema. The service user gets ALL on both through an it\_diag% grant.
const (
	diagDB       = "it_diag"
	diagROSchema = "it_diag_ro"
)

// mysqlKeptCase raises one allowlisted essno with ordinary SQL. setup and cleanup run on the same session
// around each attempt; a non-empty series limits the case to that server series.
type mysqlKeptCase struct {
	essno          uint16
	query          string
	setup, cleanup []string
	series         string
}

var (
	lockDiagLock = []string{"LOCK TABLES diag_lock READ"}
	unlockTables = []string{"UNLOCK TABLES"}
)

// mysqlKeptCases covers every essno in mysqlSchemaMessages except mysqlUnitOnlyEssnos. Unqualified names
// resolve in diagDB.
var mysqlKeptCases = []mysqlKeptCase{
	// Unknown or missing objects.
	{essno: 1008, query: "DROP DATABASE it_diag_nodb"},
	{essno: 1049, query: "CREATE TABLE it_diag_nodb.t (a INT)"},
	{essno: 1051, query: "DROP TABLE diag_nosuch"},
	{essno: 1054, query: "SELECT shipped_at FROM " + primarySchema + ".diag_orders"},
	{essno: 1072, query: "CREATE TABLE diag_new (a INT, KEY (b))"},
	{essno: 1091, query: "ALTER TABLE " + primarySchema + ".diag_orders DROP INDEX diag_no_such_index"},
	{essno: 1109, query: "DELETE x FROM diag_p"},
	{essno: 1146, query: "SELECT * FROM " + primarySchema + ".diag_no_such_table"},
	{essno: 1176, query: "SELECT * FROM diag_p USE INDEX (diag_nokey)"},
	{essno: 1305, query: "SELECT " + primarySchema + ".diag_no_such_function()"},
	{essno: 1356, query: "SELECT * FROM diag_vbroken"},
	{essno: 1539, query: "DROP EVENT diag_noevent"},
	{essno: 1630, query: "SELECT " + diagDB + ".substring('a', 1)"},
	{essno: 1735, query: "SELECT * FROM diag_part PARTITION (pnone)"},
	{essno: 1812, query: "ALTER TABLE diag_disc IMPORT TABLESPACE"},
	{essno: 1824, query: "CREATE TABLE diag_new (a INT, FOREIGN KEY (a) REFERENCES diag_nosuch (id))"},
	{essno: 3011, query: "CREATE TRIGGER diag_trg2 BEFORE INSERT ON diag_plain FOR EACH ROW FOLLOWS diag_notrg SET NEW.a = 1"},
	{essno: 3503, query: "ALTER DATABASE it_diag_nodb CHARACTER SET utf8mb4"},
	{essno: 3821, query: "ALTER TABLE diag_p DROP CHECK diag_nosuch"},
	{essno: 3940, query: "ALTER TABLE diag_p DROP CONSTRAINT diag_nosuch"},
	// Already exists or declared twice.
	{essno: 1007, query: "CREATE DATABASE " + diagDB},
	{essno: 1050, query: "CREATE TABLE " + primarySchema + ".diag_orders (a INT)"},
	{essno: 1061, query: "ALTER TABLE diag_p ADD INDEX diag_p_a (k)"},
	{essno: 1066, query: "SELECT * FROM diag_p, diag_p"},
	{essno: 1110, query: "INSERT INTO diag_plain (a, a) VALUES (1, 1)"},
	{essno: 1125, query: "INSTALL PLUGIN InnoDB SONAME 'diag_none.so'"},
	{essno: 1304, query: "CREATE PROCEDURE diag_proc() SELECT 1"},
	{essno: 1517, query: "CREATE TABLE diag_new (a INT) PARTITION BY RANGE (a) (PARTITION p0 VALUES LESS THAN (1), PARTITION p0 VALUES LESS THAN (2))"},
	{essno: 1537, query: "CREATE EVENT diag_ev ON SCHEDULE AT '2099-01-01 00:00:00' DO SELECT 1"},
	{essno: 1652, query: "CREATE TABLE diag_new (a INT) PARTITION BY KEY (a, a) PARTITIONS 2"},
	{essno: 1826, query: "CREATE TABLE diag_new (a INT, CONSTRAINT diag_c_fk FOREIGN KEY (a) REFERENCES diag_p (id))"},
	{essno: 3822, query: "CREATE TABLE diag_new (a INT, CONSTRAINT diag_dc CHECK (a > 0), CONSTRAINT diag_dc CHECK (a < 9))"},
	{essno: 4100, query: "CREATE TRIGGER IF NOT EXISTS diag_trg BEFORE INSERT ON diag_self FOR EACH ROW SET NEW.a = 1"},
	// Column references.
	{essno: 1052, query: "SELECT id FROM " + primarySchema + ".diag_orders, " + primarySchema + ".diag_items"},
	{essno: 1055, query: "SELECT status, count(*) FROM " + primarySchema + ".diag_orders GROUP BY email"},
	{essno: 1140, query: "SELECT a, count(*) FROM diag_p"},
	// NOT NULL, defaults, generated columns.
	{essno: 1048, query: "INSERT INTO " + primarySchema + ".diag_orders VALUES (2, 10, 'b', NULL, 1)"},
	{essno: 1101, query: "CREATE TABLE diag_new (a TEXT DEFAULT 'x')"},
	{essno: 1294, query: "CREATE TABLE diag_new (a INT ON UPDATE CURRENT_TIMESTAMP)"},
	{essno: 1364, query: "INSERT INTO " + primarySchema + ".diag_orders (id, amount, email, status) VALUES (3, 10, 'c', 'new')"},
	{essno: 1423, query: "INSERT INTO diag_vnodef (id) VALUES (9)"},
	{essno: 3102, query: "CREATE TABLE diag_new (a INT, b INT AS ((SELECT 1)))"},
	{essno: 3105, query: "INSERT INTO diag_g (a, g) VALUES (1, 2)"},
	{essno: 3108, query: "ALTER TABLE diag_g DROP COLUMN a"},
	{essno: 3109, query: "CREATE TABLE diag_new (id INT AUTO_INCREMENT PRIMARY KEY, g INT AS (id + 1))"},
	{essno: 3673, query: "INSERT IGNORE INTO diag_sp VALUES (NULL)"},
	// Keys and indexes.
	{essno: 1069, query: "CREATE TABLE diag_new (a INT" + repeatSQL(65, ", KEY k%d (a)") + ")"},
	{essno: 1070, query: "CREATE TABLE diag_new (" + repeatSQL(17, "c%d INT, ") + "KEY (" + repeatSQL(17, ", c%d")[2:] + "))"},
	{essno: 1071, query: "CREATE TABLE diag_new (a VARCHAR(1000), KEY (a)) CHARSET utf8mb4"},
	{essno: 1073, query: "CREATE TABLE diag_new (a TEXT, KEY (a(10))) ENGINE=ARCHIVE"},
	{essno: 1121, query: "CREATE TABLE diag_new (id INT, KEY (id)) ENGINE=ARCHIVE"},
	{essno: 1167, query: "CREATE TABLE diag_new (a CHAR(0), KEY (a))"},
	{essno: 1170, query: "CREATE TABLE diag_new (a TEXT, KEY (a))"},
	{essno: 1280, query: "CREATE TABLE diag_new (a INT, KEY `PRIMARY` (a))"},
	{essno: 1283, query: "CREATE TABLE diag_new (a INT, FULLTEXT (a))"},
	{essno: 1391, query: "CREATE TABLE diag_new (a VARCHAR(10), KEY (a(0)))"},
	{essno: 1553, query: "ALTER TABLE diag_c DROP INDEX diag_c_fk"},
	{essno: 1797, query: "CREATE TABLE diag_new (FTS_DOC_ID INT NOT NULL, a TEXT, FULLTEXT (a))"},
	{essno: 1798, query: "CREATE TABLE diag_new (FTS_DOC_ID BIGINT UNSIGNED NOT NULL, a TEXT, KEY FTS_DOC_ID_INDEX (FTS_DOC_ID), FULLTEXT (a))"},
	{essno: 3886, query: "ALTER TABLE diag_ul CONVERT TO CHARACTER SET utf8mb4"},
	{essno: 3908, query: `INSERT INTO diag_jf VALUES (1, '{"arr": [[1]]}')`},
	// Foreign keys.
	{essno: 1451, query: "DELETE FROM " + primarySchema + ".diag_orders WHERE id = 1"},
	{essno: 1452, query: "INSERT INTO " + primarySchema + ".diag_items VALUES (2, 99)"},
	{essno: 1701, query: "TRUNCATE TABLE diag_p"},
	{essno: 1822, query: "CREATE TABLE diag_new (a INT, CONSTRAINT diag_fk1 FOREIGN KEY (a) REFERENCES diag_p (k))", series: "8.0"},
	{essno: 1822, query: "CREATE TABLE diag_new (a INT, CONSTRAINT diag_fk1 FOREIGN KEY (a) REFERENCES diag_p (k))", series: "8.4",
		setup:   []string{"SET SESSION restrict_fk_on_non_standard_key = OFF"},
		cleanup: []string{"SET SESSION restrict_fk_on_non_standard_key = ON"}},
	{essno: 1828, query: "ALTER TABLE diag_c DROP COLUMN pid"},
	{essno: 1829, query: "ALTER TABLE diag_p DROP COLUMN id"},
	{essno: 1830, query: "ALTER TABLE diag_c MODIFY sid INT NOT NULL"},
	{essno: 1832, query: "ALTER TABLE diag_c MODIFY pid INT NOT NULL, ALGORITHM=COPY"},
	{essno: 1833, query: "ALTER TABLE diag_p MODIFY b VARCHAR(10) NOT NULL, ALGORITHM=COPY"},
	{essno: 3730, query: "DROP TABLE diag_p"},
	{essno: 3733, query: "CREATE TABLE diag_new (a INT, v INT AS (a) VIRTUAL, CONSTRAINT diag_fk1 FOREIGN KEY (v) REFERENCES diag_p (id))"},
	{essno: 3734, query: "CREATE TABLE diag_new (a INT, CONSTRAINT diag_fk1 FOREIGN KEY (a) REFERENCES diag_p (diag_nosuch))"},
	{essno: 3780, query: "CREATE TABLE diag_new (a VARCHAR(10), CONSTRAINT diag_fk1 FOREIGN KEY (a) REFERENCES diag_p (id))"},
	// CHECK constraints.
	{essno: 3813, query: "CREATE TABLE diag_new (a INT CHECK (b > 0), b INT)"},
	{essno: 3818, query: "CREATE TABLE diag_new (id INT AUTO_INCREMENT PRIMARY KEY, CHECK (id > 0))"},
	{essno: 3819, query: "INSERT INTO " + primarySchema + ".diag_orders VALUES (4, -1, 'd', 'new', 1)"},
	{essno: 3820, query: "CREATE TABLE diag_new (a INT, CONSTRAINT diag_ck CHECK (z > 0))"},
	{essno: 3823, query: "CREATE TABLE diag_new (a INT, CONSTRAINT diag_ck CHECK (a > 0), " +
		"CONSTRAINT diag_fk1 FOREIGN KEY (a) REFERENCES diag_p (id) ON UPDATE CASCADE)"},
	{essno: 3941, query: "ALTER TABLE diag_c ALTER CONSTRAINT diag_c_fk NOT ENFORCED"},
	{essno: 3959, query: "ALTER TABLE diag_cc DROP COLUMN a"},
	// Functional indexes, generated columns, and default expressions.
	{essno: 3754, query: "CREATE TABLE diag_new (id INT AUTO_INCREMENT PRIMARY KEY, INDEX ((id + 1)))"},
	{essno: 3755, query: "ALTER TABLE diag_fi DROP COLUMN `!hidden!diag_fi_x!0!0`"},
	{essno: 3758, query: "CREATE TABLE diag_new (a INT, INDEX ((a + RAND())))"},
	{essno: 3763, query: "CREATE TABLE diag_new (a INT, b DOUBLE AS (RAND()))"},
	{essno: 3764, query: "CREATE TABLE diag_new (a INT, b INT AS (ROW(1, 2)))"},
	{essno: 3766, query: "ALTER TABLE diag_d DROP COLUMN a"},
	{essno: 3767, query: "CREATE TABLE diag_new (a INT DEFAULT (b + 1), b INT AS (1))"},
	{essno: 3768, query: "CREATE TABLE diag_new (id INT AUTO_INCREMENT PRIMARY KEY, b INT DEFAULT (id + 1))"},
	{essno: 3769, query: "CREATE TABLE diag_new (a INT DEFAULT ((SELECT 1)))"},
	{essno: 3770, query: "CREATE TABLE diag_new (a INT DEFAULT (diag_fn(1)))"},
	{essno: 3771, query: "CREATE TABLE diag_new (a INT, b INT DEFAULT (ROW(1, 2)))"},
	{essno: 3800, query: "CREATE TABLE diag_new (a INT, INDEX ((ROW(a, 1))))"},
	{essno: 3812, query: "CREATE TABLE diag_new (a INT, CHECK (CONCAT(a)))"},
	{essno: 3814, query: "CREATE TABLE diag_new (a INT, CHECK (a < RAND()))"},
	{essno: 3815, query: "CREATE TABLE diag_new (a INT, CHECK (a < (SELECT 1)))"},
	{essno: 3837, query: "ALTER TABLE diag_fi DROP COLUMN a"},
	{essno: 3855, query: "ALTER TABLE diag_part DROP COLUMN id"},
	{essno: 3903, query: `INSERT INTO diag_jf VALUES (1, '{"arr": ["x"]}')`},
	{essno: 3904, query: `INSERT INTO diag_jf VALUES (1, '{"arr": [1e30]}')`},
	{essno: 3907, query: `INSERT INTO diag_jc VALUES ('{"a": ["abcdef"]}')`},
	// Column and type definition limits.
	{essno: 1063, query: "CREATE TABLE diag_new (a VARCHAR(10) AUTO_INCREMENT)"},
	{essno: 1074, query: "CREATE TABLE diag_new (a VARCHAR(70000))"},
	{essno: 1097, query: "CREATE TABLE diag_new (a SET(" + repeatSQL(65, ", 's%d'")[2:] + "))"},
	{essno: 1118, query: "CREATE TABLE diag_new (" + repeatSQL(5, ", c%d VARCHAR(16000)")[2:] + ") CHARSET utf8mb4"},
	{essno: 1241, query: "SELECT (1, 2) = 1"},
	{essno: 1439, query: "CREATE TABLE diag_new (a INT(300))"},
	{essno: 1628, query: "CREATE TABLE diag_new (a INT) COMMENT '" + strings.Repeat("x", 2049) + "'"},
	{essno: 1629, query: "CREATE TABLE diag_new (a INT COMMENT '" + strings.Repeat("x", 1025) + "')"},
	{essno: 1659, query: "CREATE TABLE diag_new (a FLOAT) PARTITION BY RANGE COLUMNS (a) (PARTITION p0 VALUES LESS THAN (1))"},
	{essno: 1688, query: "CREATE TABLE diag_new (a INT, KEY (a) COMMENT '" + strings.Repeat("x", 1025) + "')"},
	{essno: 1793, query: "CREATE TABLE diag_new (a INT) PARTITION BY HASH (a) (PARTITION p0 COMMENT '" + strings.Repeat("x", 1025) + "')"},
	{essno: 3013, query: "CREATE TABLE diag_new (a BIT(0))"},
	// A binary charset keeps the server's quadratic duplicate check over 65536 values to seconds.
	{essno: 3504, query: "CREATE TABLE diag_new (a ENUM(" + repeatSQL(65536, ", '%d'")[2:] + ") CHARACTER SET binary)"},
	{essno: 3505, query: "CREATE TABLE diag_new (a ENUM('" + strings.Repeat("x", 300) + "'))"},
	{essno: 3644, query: "ALTER TABLE diag_sp MODIFY g POINT NOT NULL SRID 4326"},
	// Views.
	{essno: 1288, query: "UPDATE diag_vagg SET a = 1"},
	{essno: 1347, query: "DROP VIEW diag_p"},
	{essno: 1348, query: "UPDATE diag_vexpr SET a1 = 1"},
	{essno: 1352, query: "CREATE VIEW diag_vt AS SELECT * FROM diag_tmp",
		setup: []string{"CREATE TEMPORARY TABLE diag_tmp (a INT)"}, cleanup: []string{"DROP TEMPORARY TABLE diag_tmp"}},
	{essno: 1361, query: "CREATE TRIGGER diag_tt BEFORE INSERT ON diag_tmp FOR EACH ROW SET NEW.a = 1",
		setup: []string{"CREATE TEMPORARY TABLE diag_tmp (a INT)"}, cleanup: []string{"DROP TEMPORARY TABLE diag_tmp"}},
	{essno: 1368, query: "CREATE VIEW diag_vco AS SELECT DISTINCT a FROM diag_p WITH CHECK OPTION"},
	{essno: 1369, query: "INSERT INTO diag_vchk (id, a, k) VALUES (9, -1, 1)"},
	{essno: 1393, query: "UPDATE diag_vjoin SET a = 1, sid = 1"},
	{essno: 1394, query: "INSERT INTO diag_vjoin VALUES (1, 1, 1, 1)"},
	{essno: 1395, query: "DELETE FROM diag_vjoin"},
	{essno: 1443, query: "UPDATE diag_p SET a = 1 WHERE id IN (SELECT id FROM diag_vp)"},
	{essno: 1462, query: "SELECT * FROM diag_rt"},
	{essno: 1471, query: "INSERT INTO diag_vagg (a) VALUES (1)"},
	// Routines, triggers, and events.
	{essno: 1128, query: "CREATE TABLE diag_new (t TEXT, FULLTEXT (t) WITH PARSER diag_noparser)"},
	{essno: 1320, query: "CREATE FUNCTION diag_f2() RETURNS INT DETERMINISTIC BEGIN END"},
	{essno: 1321, query: "SELECT diag_noret(0)"},
	{essno: 1458, query: "CREATE PROCEDURE `diag p ` () SELECT 1"},
	{essno: 1582, query: "SELECT ABS(1, 2)"},
	{essno: 1583, query: "SELECT ABS(1 AS x)"},
	{essno: 1584, query: "SELECT diag_fn(1 AS x)"},
	{essno: 1585, query: "CREATE FUNCTION abs RETURNS INTEGER SONAME 'diag_none.so'"},
	{essno: 3566, query: "SELECT can_access_database('mysql')"},
	{essno: 4101, query: "CREATE FUNCTION IF NOT EXISTS abs RETURNS INTEGER SONAME 'diag_none.so'"},
	// Partitions.
	{essno: 1732, query: "ALTER TABLE diag_part EXCHANGE PARTITION p0 WITH TABLE diag_q"},
	{essno: 1733, query: "ALTER TABLE diag_part EXCHANGE PARTITION p0 WITH TABLE diag_tmp",
		setup: []string{"CREATE TEMPORARY TABLE diag_tmp (id INT, a INT)"}, cleanup: []string{"DROP TEMPORARY TABLE diag_tmp"}},
	{essno: 1740, query: "ALTER TABLE diag_part EXCHANGE PARTITION p0 WITH TABLE diag_pfk"},
	// Table state.
	{essno: 1031, query: "ALTER TABLE diag_my DISCARD TABLESPACE"},
	{essno: 1093, query: "UPDATE diag_p SET a = (SELECT max(a) FROM diag_p)"},
	{essno: 1099, query: "INSERT INTO diag_lock VALUES (1)", setup: lockDiagLock, cleanup: unlockTables},
	{essno: 1100, query: "SELECT * FROM diag_p", setup: lockDiagLock, cleanup: unlockTables},
	{essno: 1114, query: "INSERT INTO diag_full VALUES (1, 'x')"},
	{essno: 1137, query: "SELECT * FROM diag_tmp x, diag_tmp y",
		setup: []string{"CREATE TEMPORARY TABLE diag_tmp (a INT) ENGINE=MyISAM"}, cleanup: []string{"DROP TEMPORARY TABLE diag_tmp"}},
	{essno: 1442, query: "INSERT INTO diag_self VALUES (1, 1)"},
	{essno: 1472, query: "SELECT * FROM diag_m2"},
	{essno: 1706, query: "UPDATE diag_p p1, diag_p p2 SET p1.id = 5, p2.a = 2 WHERE p1.id = p2.id"},
	{essno: 1746, query: "CREATE TABLE diag_new SELECT diag_ins() AS x"},
	{essno: 1809, query: "ALTER TABLE diag_systs DISCARD TABLESPACE"},
	{essno: 1814, query: "SELECT * FROM diag_disc"},
	{essno: 3989, query: "CREATE TABLE " + diagROSchema + ".t (a INT)"},
	{essno: 4092, query: "ALTER TABLE diag_ver ADD COLUMN v64 INT, ALGORITHM=INSTANT"},
	{essno: 4158, query: "ALTER TABLE diag_wide ADD COLUMN zz INT, ALGORITHM=INSTANT"},
	// Name validation and system schemas.
	{essno: 1102, query: "CREATE DATABASE `it_diag_bad `"},
	{essno: 1103, query: "CREATE TABLE `diag_bad ` (a INT)"},
	{essno: 1450, query: "RENAME TABLE diag_vp TO " + secondarySchema + ".diag_vp"},
	{essno: 3552, query: "CREATE DATABASE mysql"},
	{essno: 3554, query: "SELECT * FROM mysql.tables"},
	{essno: 3568, query: "SELECT * FROM diag_p FOR UPDATE OF diag_nosuch"},
	{essno: 3569, query: "SELECT * FROM diag_p FOR UPDATE OF diag_p FOR SHARE OF diag_p"},
	// Charsets, collations, and engines.
	{essno: 1253, query: "SELECT _utf8mb4'a' COLLATE latin1_swedish_ci"},
	{essno: 1267, query: "SELECT _latin1'a' COLLATE latin1_bin = _latin1'a' COLLATE latin1_general_ci"},
	{essno: 1270, query: "SELECT ELT(1, _latin1'a' COLLATE latin1_bin, _latin1'a' COLLATE latin1_general_ci, _latin1'b' COLLATE latin1_german1_ci)"},
	{essno: 1271, query: "SELECT CONCAT(_latin1'a' COLLATE latin1_bin, _latin1'a' COLLATE latin1_general_ci, " +
		"_latin1'b' COLLATE latin1_german1_ci, _latin1'c' COLLATE latin1_danish_ci)"},
	{essno: 3981, query: "CREATE TABLE diag_new (a INT) ENGINE=MyISAM ENGINE_ATTRIBUTE='{}'"},
}

// mysqlUnitOnlyEssnos are the allowlisted codes ordinary SQL on a test server cannot raise as an error.
var mysqlUnitOnlyEssnos = []struct {
	essno  int
	reason string
}{
	{1106, "not raised by 8.0 or 8.4 (PROCEDURE ANALYSE was removed)"},
	{1107, "not raised by 8.0 or 8.4 (PROCEDURE ANALYSE was removed)"},
	{1108, "not raised by 8.0 or 8.4 (PROCEDURE ANALYSE was removed)"},
	{1603, "not raised by 8.0 or 8.4"},
	{3856, "a warning on 8.0; 8.4 rejects FLOAT AUTO_INCREMENT with 1063"},
	{4129, "LOAD DATA ALGORITHM=BULK only; Community Server does not support it"},
	{4130, "LOAD DATA ALGORITHM=BULK only; Community Server does not support it"},
	{4131, "LOAD DATA ALGORITHM=BULK only; Community Server does not support it"},
	{4132, "LOAD DATA ALGORITHM=BULK only; Community Server does not support it"},
	{1082, "a warning only"},
	{1266, "a warning only"},
	{1276, "a note only"},
	{1599, "a note only"},
	{1600, "a note only"},
	{1604, "a warning only"},
	{1605, "a warning only"},
	{1684, "INFORMATION_SCHEMA reads turn it into a warning"},
	{1739, "a warning only"},
	{1831, "a warning only"},
	{3010, "a warning only"},
	{3674, "a warning only"},
	{3778, "a warning only"},
	{3909, "a warning only"},
	{4079, "a warning only"},
	{4084, "a note only"},
	{4099, "a note only"},
	{3817, "the non-boolean check (3812) rejects a top-level ROW first"},
	{1709, "the SQL layer rejects the same index with 1071 first"},
	{1825, "the SQL layer rejects the same foreign key with 1830 first"},
	{1821, "the server always generates the child's supporting index"},
	{1823, "InnoDB failure adding a foreign key to a system table; debug builds only"},
	{1022, "InnoDB always names the duplicate key (1062)"},
	{1169, "MyISAM hash-unique constraints back internal temporary tables only"},
	{1307, "a routine lock timeout reports 1205 first; otherwise a data-dictionary write failure"},
	{1334, "a routine lock timeout reports 1205 first; otherwise a data-dictionary write failure"},
	{3512, "a routine lock timeout reports 1205 first; otherwise a data-dictionary read failure"},
	{1606, "the table's own open error is reported first"},
	{1312, "needs a client without CLIENT_MULTI_RESULTS"},
	{1454, "the replication applier only"},
	{1437, "a routine body over the storage limit; debug builds only"},
	{1122, "a loadable function whose library is no longer loaded"},
	{1306, "a mysql.func write failure while dropping a loadable function"},
	{1799, "an online ALTER whose concurrent DML outgrows innodb_online_alter_log_max_size"},
	{1859, "an online ALTER racing a duplicate insert"},
	{1807, "DISCARD TABLESPACE racing a foreign key check"},
	{1020, "a MyISAM record changed under the handler"},
	{1032, "a storage-engine record lookup failure"},
	{1036, "a table opened from read-only files"},
	{1112, "a table using an unsupported storage-engine extension"},
	{1194, "a crashed MyISAM table"},
	{1195, "a crashed MyISAM table"},
	{1459, "a table created by an older server"},
	{1707, "a table created by an older server"},
	{3009, "a system table created by an older server"},
	{1712, "a corrupt index"},
	{1728, "a corrupt system table"},
	{1805, "a corrupt system table"},
	{1877, "a corrupt system table"},
	{1886, "a system table missing its keys"},
	{1682, "a performance_schema table with the wrong structure"},
	{3003, "a table whose storage engine is not loaded"},
	{3014, "an engine create option; no such engine ships loaded"},
	{3015, "a storage engine out of memory"},
	{3161, "disabled_storage_engines is a startup option"},
	{3604, "a storage-engine drop failure"},
	{3605, "a table missing from its storage engine"},
	{3609, "IMPORT TABLE needs an .sdi file on the server's filesystem"},
	{3610, "IMPORT TABLE needs an .sdi file on the server's filesystem"},
	{3624, "a histogram write failure"},
	{3625, "a histogram write failure"},
	{3626, "a histogram write failure"},
	{3627, "a histogram write failure"},
}

func repeatSQL(n int, format string) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, format, i)
	}
	return b.String()
}

// seedMysqlDiagSchema builds diagDB as root. Under binary logging a trigger needs SUPER unless
// log_bin_trust_function_creators is on.
func seedMysqlDiagSchema(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	conn, err := dbtest.OpenMySQL(t, "").Conn(ctx)
	if err != nil {
		t.Fatalf("root conn: %v", err)
	}
	defer conn.Close()
	svc := "'" + serviceUser + "'@'%'"
	statements := []string{
		"DROP DATABASE IF EXISTS " + diagDB,
		"CREATE DATABASE " + diagDB,
		"CREATE DATABASE IF NOT EXISTS " + diagROSchema,
		"ALTER SCHEMA " + diagROSchema + " READ ONLY = 1",
		"GRANT ALL ON `it\\_diag%`.* TO " + svc,
		"GRANT CREATE ON mysql.* TO " + svc,
		"GRANT INSERT ON mysql.plugin TO " + svc,
		"SET GLOBAL log_bin_trust_function_creators = 1",
		"USE " + diagDB,
		"CREATE TABLE diag_p (id INT PRIMARY KEY, a INT, b VARCHAR(10), j JSON, k INT NOT NULL, " +
			"UNIQUE KEY diag_p_b (b), KEY diag_p_a (a), CONSTRAINT diag_p_chk CHECK (a > 0))",
		`INSERT INTO diag_p VALUES (1, 1, 'x', '{"a": 1}', 1), (2, 2, 'z', '{"a": 2}', 2)`,
		"CREATE TABLE diag_c (id INT PRIMARY KEY, pid INT, sid INT, " +
			"CONSTRAINT diag_c_fk FOREIGN KEY (pid) REFERENCES diag_p (id), " +
			"CONSTRAINT diag_c_fk2 FOREIGN KEY (sid) REFERENCES diag_p (id) ON DELETE SET NULL)",
		"INSERT INTO diag_c VALUES (1, 1, 1)",
		"CREATE TABLE diag_fkb (id INT, pb VARCHAR(10), CONSTRAINT diag_fkb_fk FOREIGN KEY (pb) REFERENCES diag_p (b))",
		"CREATE TABLE diag_pfk (id INT PRIMARY KEY, pid INT, CONSTRAINT diag_pfk_fk FOREIGN KEY (pid) REFERENCES diag_p (id))",
		"CREATE TABLE diag_g (a INT, g INT AS (a + 1))",
		"CREATE TABLE diag_d (a INT, b INT DEFAULT (a + 1))",
		"CREATE TABLE diag_fi (id INT, a INT, INDEX diag_fi_x ((a + 1)))",
		"CREATE TABLE diag_cc (a INT, b INT, CONSTRAINT diag_cc_ab CHECK (a < b))",
		"CREATE TABLE diag_sp (g POINT NOT NULL SRID 0, SPATIAL INDEX (g))",
		"CREATE TABLE diag_ul (a VARCHAR(1000), UNIQUE KEY diag_ul_a (a)) CHARSET latin1",
		"CREATE TABLE diag_jf (id INT, j JSON, INDEX diag_jf_a ((CAST(j->'$.arr' AS UNSIGNED ARRAY))))",
		"CREATE TABLE diag_jc (j JSON, INDEX ((CAST(j->'$.a' AS CHAR(3) ARRAY))))",
		"CREATE TABLE diag_part (id INT, a INT) PARTITION BY RANGE (id) (PARTITION p0 VALUES LESS THAN (10), PARTITION p1 VALUES LESS THAN MAXVALUE)",
		"CREATE TABLE diag_q (id INT, a INT) PARTITION BY HASH (id) PARTITIONS 2",
		"CREATE TABLE diag_plain (id INT, a INT)",
		"CREATE TRIGGER diag_trg BEFORE INSERT ON diag_plain FOR EACH ROW SET NEW.a = NEW.a",
		"CREATE TABLE diag_self (id INT, a INT)",
		"CREATE TRIGGER diag_self_trg AFTER INSERT ON diag_self FOR EACH ROW INSERT INTO diag_self VALUES (0, 0)",
		"CREATE TABLE diag_lock (id INT)",
		"CREATE TABLE diag_my (id INT) ENGINE=MyISAM",
		"CREATE TABLE diag_m0 (id INT) ENGINE=MyISAM",
		"CREATE TABLE diag_m1 (id INT) ENGINE=MERGE UNION=(diag_m0)",
		"CREATE TABLE diag_m2 (id INT) ENGINE=MERGE UNION=(diag_m1)",
		"CREATE TABLE diag_disc (id INT)",
		"ALTER TABLE diag_disc DISCARD TABLESPACE",
		"CREATE TABLE diag_systs (id INT) TABLESPACE innodb_system",
		"CREATE TABLE diag_base (a INT)",
		"CREATE VIEW diag_vbroken AS SELECT a FROM diag_base",
		"DROP TABLE diag_base",
		"CREATE TABLE diag_rt (x INT)",
		"CREATE VIEW diag_rv AS SELECT * FROM diag_rt",
		"DROP TABLE diag_rt",
		"RENAME TABLE diag_rv TO diag_rt",
		"CREATE VIEW diag_vagg AS SELECT a, count(*) AS n FROM diag_p GROUP BY a",
		"CREATE VIEW diag_vexpr AS SELECT id, a + 1 AS a1 FROM diag_p",
		"CREATE VIEW diag_vchk AS SELECT id, a, k FROM diag_p WHERE a > 0 WITH CHECK OPTION",
		"CREATE VIEW diag_vjoin AS SELECT p.id AS pid, p.a, c.id AS cid, c.sid FROM diag_p p JOIN diag_c c ON c.pid = p.id",
		"CREATE VIEW diag_vnodef AS SELECT id, a FROM diag_p",
		"CREATE VIEW diag_vp AS SELECT * FROM diag_p",
		"CREATE PROCEDURE diag_proc() SELECT 1",
		"CREATE FUNCTION diag_fn(x INT) RETURNS INT DETERMINISTIC RETURN x",
		"CREATE FUNCTION diag_noret(x INT) RETURNS INT DETERMINISTIC BEGIN IF x THEN RETURN 1; END IF; END",
		"CREATE FUNCTION diag_ins() RETURNS INT DETERMINISTIC BEGIN INSERT INTO diag_lock VALUES (1); RETURN 1; END",
		"CREATE EVENT diag_ev ON SCHEDULE AT '2099-01-01 00:00:00' ON COMPLETION PRESERVE DISABLE DO SELECT 1",
		"CREATE TABLE diag_ver (id INT PRIMARY KEY)",
		"INSERT INTO diag_ver VALUES (1)",
	}
	for i := 0; i < 64; i++ {
		statements = append(statements, fmt.Sprintf("ALTER TABLE diag_ver ADD COLUMN v%d INT, ALGORITHM=INSTANT", i))
	}
	statements = append(statements,
		"CREATE TABLE diag_wide (id INT PRIMARY KEY"+repeatSQL(1016, ", c%d INT")+")",
		"INSERT INTO diag_wide (id) VALUES (1)",
		"ALTER TABLE diag_wide DROP COLUMN c0, DROP COLUMN c1, ALGORITHM=INSTANT",
		"CREATE TABLE diag_cnt (id INT)",
		"INSERT INTO diag_cnt VALUES (1), (2), (3), (4), (5), (6), (7), (8), (9), (10)",
		"SET SESSION max_heap_table_size = 16384",
		"CREATE TABLE diag_full (id INT, pad CHAR(200)) ENGINE=MEMORY",
	)
	for _, statement := range statements {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			t.Fatalf("seed %q: %v", statement, err)
		}
	}
	var full *mysqldriver.MySQLError
	if _, err := conn.ExecContext(ctx, "INSERT INTO diag_full SELECT a.id, 'x' FROM diag_cnt a, diag_cnt b, diag_cnt c"); !errors.As(err, &full) || full.Number != 1114 {
		t.Fatalf("filling diag_full: %v, want 1114", err)
	}
}

// End-to-end through the real proxy and target DB: on a diagnostic-redacted connection every allowlisted
// error a test server can raise reaches the client exactly as the target DB sent it, and an error that
// echoes a stored value or a statement fragment carries only its essno symbol. The control connection
// (no redaction) proves each case raises its listed template, and each value case genuinely leaks. Run
// against every MySQL series in db-support.json via PM_TEST_MYSQL_IMAGE. See docs/diagnostic-redaction.md.
func TestDiagnosticRedactionMysqlErrPacketEndToEnd(t *testing.T) {
	h := startBroker(t)
	var sanitize atomic.Bool
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, SanitizeDiagnostics: sanitize.Load()}), nil
	}
	const sentinel = "010-1234-5678"
	s := primarySchema
	seedMysqlDiagSchema(t)

	db := h.openDBInDatabase(t, validToken, diagDB)
	for _, ddl := range []string{
		"DROP TABLE IF EXISTS " + s + ".diag_items",
		"DROP TABLE IF EXISTS " + s + ".diag_orders",
		"CREATE TABLE " + s + ".diag_orders (id INT PRIMARY KEY, amount INT, email VARCHAR(64) UNIQUE, " +
			"status VARCHAR(16) NOT NULL, created INT NOT NULL, CONSTRAINT diag_amount_positive CHECK (amount > 0))",
		"CREATE TABLE " + s + ".diag_items (id INT, order_id INT, " +
			"CONSTRAINT diag_items_order_fk FOREIGN KEY (order_id) REFERENCES " + s + ".diag_orders (id))",
		"INSERT INTO " + s + ".diag_orders VALUES (1, 10, '" + sentinel + "', 'paid', 1)",
		"INSERT INTO " + s + ".diag_items VALUES (1, 1)",
	} {
		if _, err := db.Exec(ddl); err != nil {
			t.Fatalf("seed %q: %v", ddl, err)
		}
	}
	var version string
	if err := db.QueryRow("SELECT VERSION()").Scan(&version); err != nil {
		t.Fatalf("SELECT VERSION(): %v", err)
	}
	run := func(redact bool, c mysqlKeptCase) (*mysqldriver.MySQLError, error) {
		t.Helper()
		sanitize.Store(redact)
		for _, q := range c.setup {
			if _, err := db.Exec(q); err != nil {
				t.Fatalf("%s: setup %q: %v", c.query, q, err)
			}
		}
		_, err := db.Exec(c.query)
		for _, q := range c.cleanup {
			if _, cerr := db.Exec(q); cerr != nil {
				t.Fatalf("%s: cleanup %q: %v", c.query, q, cerr)
			}
		}
		var myErr *mysqldriver.MySQLError
		if !errors.As(err, &myErr) {
			return nil, fmt.Errorf("error = %T %v, want *mysqldriver.MySQLError", err, err)
		}
		return myErr, nil
	}

	ran := map[uint16]bool{}
	for _, c := range mysqlKeptCases {
		if c.series != "" && !strings.HasPrefix(version, c.series+".") {
			continue
		}
		ran[c.essno] = true
		raw, err := run(false, c)
		if err != nil {
			t.Errorf("%d %s: control %v", c.essno, c.query, err)
			continue
		}
		got, err := run(true, c)
		if err != nil {
			t.Errorf("%d %s: redacted %v", c.essno, c.query, err)
			continue
		}
		if raw.Number != c.essno || got.Number != c.essno {
			t.Errorf("%d %s: essno raw=%d %q redacted=%d", c.essno, c.query, raw.Number, raw.Message, got.Number)
			continue
		}
		if !mysql.MatchesSchemaTemplate(int(c.essno), raw.Message) {
			t.Errorf("%d: target DB message %q does not match its allowlisted template", c.essno, raw.Message)
		}
		if got.Message != raw.Message {
			t.Errorf("%d: redacted message = %q, want the target DB message %q", c.essno, got.Message, raw.Message)
		}
	}
	for _, c := range mysqlKeptCases {
		if !ran[c.essno] {
			t.Errorf("%d: no case for server %s", c.essno, version)
		}
	}

	stripped := []struct {
		essno  uint16
		symbol string
		query  string
	}{
		{1062, "ER_DUP_ENTRY", "INSERT INTO " + s + ".diag_orders VALUES (5, 10, '" + sentinel + "', 'new', 1)"},
		{1366, "ER_TRUNCATED_WRONG_VALUE_FOR_FIELD", "INSERT INTO " + s + ".diag_orders VALUES (6, 'x" + sentinel + "', 'f', 'new', 1)"},
		{1064, "ER_PARSE_ERROR", "SELECT * FROM " + s + ".diag_orders WHERE email = = '" + sentinel + "'"},
		{3511, relay.RedactedDiagnosticMessage, "CREATE PROCEDURE diag_long() COMMENT '" + sentinel + strings.Repeat("x", 65536) + "' SELECT 1"},
	}
	for _, c := range stripped {
		raw, err := run(false, mysqlKeptCase{query: c.query})
		if err != nil {
			t.Errorf("%d: control %v", c.essno, err)
			continue
		}
		if !strings.Contains(raw.Message, sentinel) {
			t.Errorf("%d: control message %q does not echo the value; the case is not exercising a leak", c.essno, raw.Message)
		}
		got, err := run(true, mysqlKeptCase{query: c.query})
		if err != nil {
			t.Errorf("%d: redacted %v", c.essno, err)
			continue
		}
		if got.Number != c.essno || got.Message != c.symbol {
			t.Errorf("%d: redacted = %d %q, want %d %q", c.essno, got.Number, got.Message, c.essno, c.symbol)
		}
	}
}

// Every allowlisted essno is either raised end to end above or consciously listed as unit-only.
func TestMysqlSchemaMessagesCoveredEndToEnd(t *testing.T) {
	covered := map[int]string{}
	for _, c := range mysqlKeptCases {
		covered[int(c.essno)] = "e2e"
	}
	for _, u := range mysqlUnitOnlyEssnos {
		if _, dup := covered[u.essno]; dup {
			t.Errorf("essno %d is both raised end to end and listed unit-only", u.essno)
		}
		covered[u.essno] = u.reason
	}
	allowlisted := map[int]bool{}
	for _, essno := range mysql.SchemaMessageEssnos() {
		allowlisted[essno] = true
		if _, ok := covered[essno]; !ok {
			t.Errorf("allowlisted essno %d has no end-to-end case and is not listed unit-only", essno)
		}
	}
	for essno := range covered {
		if !allowlisted[essno] {
			t.Errorf("essno %d is covered but not allowlisted", essno)
		}
	}
}

// The error-based extraction attack confirmed in the field — `extractvalue(1, concat(0x7e,
// (SELECT <masked col> …)))` puts the stored value directly into a 1105 XPATH error message, returned on the
// query itself with no SHOW WARNINGS / GET DIAGNOSTICS read-back. This is defense-in-depth behind the CP's
// own lineage enforcement (a masked column in a non-output position is denied before the statement runs);
// this test isolates the redaction layer with an allow-all fake CP to prove the ERR-packet strip still
// removes the value if the statement ever reaches the target DB.
func TestDiagnosticRedactionStripsErrorBasedExtractionEndToEnd(t *testing.T) {
	h := startBroker(t)
	var sanitize atomic.Bool
	h.fake.decideFn = func(*pb.DecisionRequest) (*pb.WireDecision, error) {
		return wireVerdict(&pb.Verdict{Decision: pb.EnfAction_ALLOW, SanitizeDiagnostics: sanitize.Load()}), nil
	}
	const sentinel = "010-1234-5678"

	sanitize.Store(true)
	redacted := h.openDB(t, validToken)
	for _, ddl := range []string{
		"DROP TABLE IF EXISTS " + primarySchema + ".diag_xxe",
		"CREATE TABLE " + primarySchema + ".diag_xxe (secret VARCHAR(64))",
		"INSERT INTO " + primarySchema + ".diag_xxe VALUES ('" + sentinel + "')",
	} {
		if _, err := redacted.Exec(ddl); err != nil {
			t.Fatalf("seed %q: %v", ddl, err)
		}
	}
	xxe := "SELECT extractvalue(1, concat(0x7e, (SELECT secret FROM " + primarySchema + ".diag_xxe LIMIT 1)))"

	// Redacted: the 1105 XPATH error must reach the client stripped of the extracted value.
	_, err := redacted.Exec(xxe)
	var myErr *mysqldriver.MySQLError
	if err == nil || !errors.As(err, &myErr) {
		t.Fatalf("error = %T %v, want *mysqldriver.MySQLError", err, err)
	}
	if myErr.Message != "ER_UNKNOWN_ERROR" {
		t.Errorf("message = %q, want the essno symbol (ER_UNKNOWN_ERROR is the extractvalue catch-all)", myErr.Message)
	}
	if strings.Contains(myErr.Message, sentinel) {
		t.Errorf("error-based extraction leaked the stored value through the redacted message: %q", myErr.Message)
	}

	// Control: without redaction the 1105 error echoes the stored value, proving the attack is genuine.
	sanitize.Store(false)
	plain := h.openDB(t, validToken)
	_, err = plain.Exec(xxe)
	if err == nil || !errors.As(err, &myErr) {
		t.Fatalf("control error = %T %v, want *mysqldriver.MySQLError", err, err)
	}
	if !strings.Contains(myErr.Message, sentinel) {
		t.Fatalf("control did not leak the stored value (%q) — not exercising the real attack", myErr.Message)
	}
}
