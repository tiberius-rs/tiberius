use futures_util::io::{AsyncRead, AsyncWrite};
use names::{Generator, Name};
use once_cell::sync::Lazy;
use std::cell::RefCell;
use std::env;
use std::sync::Once;
use tiberius::ColumnData;
use tiberius::{IntoSql, Result, TokenRow};

#[cfg(all(feature = "tds73", feature = "chrono"))]
use chrono::DateTime;
#[cfg(all(feature = "tds73", feature = "chrono"))]
use chrono::NaiveDateTime;

use runtimes_macro::test_on_runtimes;

// This is used in the testing macro :)
#[allow(dead_code)]
static LOGGER_SETUP: Once = Once::new();

static CONN_STR: Lazy<String> = Lazy::new(|| {
    env::var("TIBERIUS_TEST_CONNECTION_STRING").unwrap_or_else(|_| {
        "server=tcp:localhost,1433;IntegratedSecurity=true;TrustServerCertificate=true".to_owned()
    })
});

thread_local! {
    static NAMES: RefCell<Option<Generator<'static>>> =
        const { RefCell::new(None) };
}

async fn random_table() -> String {
    NAMES.with(|maybe_generator| {
        maybe_generator
            .borrow_mut()
            .get_or_insert_with(|| Generator::with_naming(Name::Plain))
            .next()
            .unwrap()
            .replace('-', "")
    })
}

macro_rules! test_bulk_type {
    ($name:ident($sql_type:literal, $total_generated:expr, $generator:expr)) => {
        paste::item! {
            #[test_on_runtimes]
            async fn [< bulk_load_optional_ $name >]<S>(mut conn: tiberius::Client<S>) -> Result<()>
            where
                S: AsyncRead + AsyncWrite + Unpin + Send,
            {
                let table = format!("##{}", random_table().await);

                conn.execute(
                    &format!(
                        "CREATE TABLE {} (id INT IDENTITY PRIMARY KEY, content {} NULL)",
                        table,
                        $sql_type,
                    ),
                    &[],
                )
                    .await?;

                let mut req = conn.bulk_insert(&table).await?;

                for i in $generator {
                    let mut row = TokenRow::new();
                    row.push(i.into_sql());
                    req.send(row).await?;
                }

                let res = req.finalize().await?;

                assert_eq!($total_generated, res.total());

                Ok(())
            }

            #[test_on_runtimes]
            async fn [< bulk_load_required_ $name >]<S>(mut conn: tiberius::Client<S>) -> Result<()>
            where
                S: AsyncRead + AsyncWrite + Unpin + Send,
            {
                let table = format!("##{}", random_table().await);

                conn.execute(
                    &format!(
                        "CREATE TABLE {} (id INT IDENTITY PRIMARY KEY, content {} NOT NULL)",
                        table,
                        $sql_type
                    ),
                    &[],
                )
                    .await?;

                let mut req = conn.bulk_insert(&table).await?;

                for i in $generator {
                    let mut row = TokenRow::new();
                    row.push(i.into_sql());
                    req.send(row).await?;
                }

                let res = req.finalize().await?;

                assert_eq!($total_generated, res.total());

                Ok(())
            }
        }
    };
}

test_bulk_type!(tinyint("TINYINT", 256, 0..=255u8));
test_bulk_type!(smallint("SMALLINT", 2000, 0..2000i16));
test_bulk_type!(int("INT", 2000, 0..2000i32));
test_bulk_type!(bigint("BIGINT", 2000, 0..2000i64));

test_bulk_type!(empty_varchar(
    "VARCHAR(MAX)",
    100,
    vec![""; 100].into_iter()
));
test_bulk_type!(empty_nvarchar(
    "NVARCHAR(MAX)",
    100,
    vec![""; 100].into_iter()
));
test_bulk_type!(empty_varbinary(
    "VARBINARY(MAX)",
    100,
    vec![b""; 100].into_iter()
));

test_bulk_type!(real(
    "REAL",
    1000,
    vec![std::f32::consts::PI; 1000].into_iter()
));

test_bulk_type!(float(
    "FLOAT",
    1000,
    vec![std::f64::consts::PI; 1000].into_iter()
));

test_bulk_type!(varchar_limited(
    "VARCHAR(255)",
    1000,
    vec!["aaaaaaaaaaaaaaaaaaaaaaa"; 1000].into_iter()
));

// Column types added by 97bbbfd (bulk support for #352/#358) that previously
// had no bulk coverage. `text`/`ntext` exercise the COLMETADATA TableName path
// (MS-TDS §2.2.7.4): without emitting TableName for these types the server
// rejects the bulk COLMETADATA, so these tests only pass with that fix in place.
test_bulk_type!(text(
    "TEXT",
    1000,
    vec!["some text value"; 1000].into_iter()
));
test_bulk_type!(ntext(
    "NTEXT",
    1000,
    vec!["some ntext välue"; 1000].into_iter()
));

// `money`/`smallmoney` exercise the f64 money encoder.
test_bulk_type!(money("MONEY", 1000, vec![1234.5678f64; 1000].into_iter()));
test_bulk_type!(smallmoney(
    "SMALLMONEY",
    1000,
    vec![12.3456f64; 1000].into_iter()
));

// `numeric(p,s)` exercises the exact Numeric->wire path.
test_bulk_type!(numeric_28_4(
    "NUMERIC(28,4)",
    1000,
    vec![tiberius::numeric::Numeric::new_with_scale(12345, 4); 1000].into_iter()
));

// The `test_bulk_type!` cases above only assert the inserted row count. The
// following tests bulk-insert a known value and read it back, asserting the
// exact value survived the round-trip through our bulk encoders. (Requires a
// live SQL Server; compiles locally but only runs in CI.)

#[test_on_runtimes]
async fn bulk_money_value_roundtrips<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = format!("##{}", random_table().await);

    conn.execute(
        &format!("CREATE TABLE {} (content MONEY NOT NULL)", table),
        &[],
    )
    .await?;

    let mut req = conn.bulk_insert(&table).await?;
    let mut row = TokenRow::new();
    row.push(1234.5678f64.into_sql());
    req.send(row).await?;
    let res = req.finalize().await?;
    assert_eq!(1, res.total());

    let row = conn
        .query(&format!("SELECT content FROM {}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    #[cfg(not(feature = "exact-money"))]
    {
        let value: f64 = row.get(0).unwrap();
        assert!((value - 1234.5678).abs() < 1e-6, "got {value}");
    }

    #[cfg(feature = "exact-money")]
    {
        let value: tiberius::numeric::Numeric = row.get(0).unwrap();
        assert_eq!(
            tiberius::numeric::Numeric::new_with_scale(12_345_678, 4),
            value
        );
    }

    Ok(())
}

#[test_on_runtimes]
async fn bulk_numeric_value_roundtrips<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use tiberius::numeric::Numeric;

    let table = format!("##{}", random_table().await);

    conn.execute(
        &format!("CREATE TABLE {} (content NUMERIC(28,4) NOT NULL)", table),
        &[],
    )
    .await?;

    // A magnitude whose scaled form exceeds 2^53, so an f64 detour would lose
    // precision but the exact integer path must not.
    let num = Numeric::new_with_scale(123_456_789_012_345_678, 4);

    let mut req = conn.bulk_insert(&table).await?;
    let mut row = TokenRow::new();
    row.push(num.into_sql());
    req.send(row).await?;
    let res = req.finalize().await?;
    assert_eq!(1, res.total());

    let value: Numeric = conn
        .query(&format!("SELECT content FROM {}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap()
        .get(0)
        .unwrap();

    assert_eq!(value, num);

    Ok(())
}

#[test_on_runtimes]
async fn bulk_text_value_roundtrips<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = format!("##{}", random_table().await);

    conn.execute(
        &format!("CREATE TABLE {} (content TEXT NOT NULL)", table),
        &[],
    )
    .await?;

    let expected = "hello bulk text";
    let mut req = conn.bulk_insert(&table).await?;
    let mut row = TokenRow::new();
    row.push(expected.into_sql());
    req.send(row).await?;
    let res = req.finalize().await?;
    assert_eq!(1, res.total());

    let row = conn
        .query(&format!("SELECT content FROM {}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();
    let value: &str = row.get(0).unwrap();

    assert_eq!(value, expected);

    Ok(())
}

#[test_on_runtimes]
async fn bulk_ntext_value_roundtrips<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = format!("##{}", random_table().await);

    conn.execute(
        &format!("CREATE TABLE {} (content NTEXT NOT NULL)", table),
        &[],
    )
    .await?;

    let expected = "héllo bulk ñtext";
    let mut req = conn.bulk_insert(&table).await?;
    let mut row = TokenRow::new();
    row.push(expected.into_sql());
    req.send(row).await?;
    let res = req.finalize().await?;
    assert_eq!(1, res.total());

    let row = conn
        .query(&format!("SELECT content FROM {}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();
    let value: &str = row.get(0).unwrap();

    assert_eq!(value, expected);

    Ok(())
}

/// Bulk-insert "Привет" into Cyrillic_General_CI_AS (CP1251) columns of
/// `table` and check the stored bytes. The database default collation must
/// not use CP1251 for this to detect a missing `COLLATE` in `INSERT BULK`:
/// the server would then read the CP1251 bytes in the default code page.
async fn bulk_cyrillic_roundtrip<S>(conn: &mut tiberius::Client<S>, table: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let default_code_page = conn
        .query(
            "SELECT CONVERT(INT, COLLATIONPROPERTY(CONVERT(NVARCHAR(128), \
             DATABASEPROPERTYEX(DB_NAME(), 'Collation')), 'CodePage'))",
            &[],
        )
        .await?
        .into_row()
        .await?
        .unwrap()
        .get::<i32, _>(0);
    assert_ne!(Some(1251), default_code_page);

    // A plain batch, not `execute`: a `#` temp table created inside the
    // sp_executesql call `execute` sends is dropped when that call returns.
    conn.simple_query(format!(
        "CREATE TABLE {} (id INT NOT NULL, \
         v VARCHAR(20) COLLATE Cyrillic_General_CI_AS NOT NULL, \
         c CHAR(6) COLLATE Cyrillic_General_CI_AS NOT NULL, \
         t TEXT COLLATE Cyrillic_General_CI_AS NOT NULL, \
         n NVARCHAR(20) COLLATE Cyrillic_General_CI_AS NOT NULL)",
        table
    ))
    .await?
    .into_results()
    .await?;

    let expected = "Привет";
    let mut req = conn.bulk_insert(table).await?;
    let mut row = TokenRow::new();
    row.push(1i32.into_sql());
    row.push(expected.into_sql());
    row.push(expected.into_sql());
    row.push(expected.into_sql());
    row.push(expected.into_sql());
    req.send(row).await?;
    assert_eq!(1, req.finalize().await?.total());

    let row = conn
        .query(
            &format!(
                "SELECT v, c, t, n, CONVERT(VARBINARY(20), v), CONVERT(VARBINARY(20), c), \
                 CONVERT(VARBINARY(20), CONVERT(VARCHAR(20), t)) FROM {}",
                table
            ),
            &[],
        )
        .await?
        .into_row()
        .await?
        .unwrap();

    let cp1251: &[u8] = &[0xCF, 0xF0, 0xE8, 0xE2, 0xE5, 0xF2];
    assert_eq!(Some(expected), row.get::<&str, _>(0));
    assert_eq!(Some(expected), row.get::<&str, _>(1));
    assert_eq!(Some(expected), row.get::<&str, _>(2));
    assert_eq!(Some(expected), row.get::<&str, _>(3));
    assert_eq!(Some(cp1251), row.get::<&[u8], _>(4));
    assert_eq!(Some(cp1251), row.get::<&[u8], _>(5));
    assert_eq!(Some(cp1251), row.get::<&[u8], _>(6));

    Ok(())
}

#[test_on_runtimes]
async fn bulk_text_keeps_a_non_default_column_collation<S>(
    mut conn: tiberius::Client<S>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // A table in the current database, named with its schema.
    let table = format!("dbo.bulk_collate_{}", random_table().await);

    let result = bulk_cyrillic_roundtrip(&mut conn, &table).await;
    drop_table(&mut conn, &format!("N'{table}'"), &table).await?;

    result
}

/// Drops `table`, whose `OBJECT_ID` name is `object_name`, in a plain batch.
async fn drop_table<S>(conn: &mut tiberius::Client<S>, object_name: &str, table: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    conn.simple_query(format!(
        "IF OBJECT_ID({object_name}) IS NOT NULL DROP TABLE {table}"
    ))
    .await?
    .into_results()
    .await?;

    Ok(())
}

#[test_on_runtimes]
async fn bulk_text_keeps_a_non_default_column_collation_in_a_temp_table<S>(
    mut conn: tiberius::Client<S>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = format!("#{}", random_table().await);

    let result = bulk_cyrillic_roundtrip(&mut conn, &table).await;
    drop_table(&mut conn, &format!("N'tempdb..{table}'"), &table).await?;

    result
}

/// Bulk-insert every byte 0x80..=0xFF of the code page of `collation`, as
/// text decoded by the client, into char, varchar, varchar(max) and text
/// columns of the # temp table `table` and check the stored bytes.
async fn bulk_every_high_byte_roundtrip<S>(
    conn: &mut tiberius::Client<S>,
    table: &str,
    collation: &str,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let bytes: Vec<u8> = (0x80..=0xFF).collect();
    let hex: String = bytes.iter().map(|b| format!("{b:02X}")).collect();

    conn.simple_query(format!(
        "CREATE TABLE {table} (c CHAR(128) COLLATE {collation} NOT NULL, \
         v VARCHAR(128) COLLATE {collation} NOT NULL, \
         m VARCHAR(MAX) COLLATE {collation} NOT NULL, \
         t TEXT COLLATE {collation} NOT NULL)"
    ))
    .await?
    .into_results()
    .await?;

    // The text of the 128 bytes: a varchar value of the collation (a binary
    // value converts to it byte for byte), decoded by the client, and the
    // server's own decoding of it for comparison.
    let row = conn
        .simple_query(format!(
            "DECLARE @t TABLE (v VARCHAR(128) COLLATE {collation}); \
             INSERT INTO @t VALUES (0x{hex}); \
             SELECT v, CONVERT(NVARCHAR(128), v), CONVERT(VARBINARY(128), v) FROM @t"
        ))
        .await?
        .into_row()
        .await?
        .unwrap();
    assert_eq!(
        Some(bytes.as_slice()),
        row.get::<&[u8], _>(2),
        "{collation}"
    );
    let text = row.get::<&str, _>(0).unwrap().to_owned();
    assert_eq!(Some(text.as_str()), row.get::<&str, _>(1), "{collation}");
    assert_eq!(128, text.chars().count(), "{collation}");

    let mut req = conn.bulk_insert(table).await?;
    let mut row = TokenRow::new();
    for _ in 0..4 {
        row.push(text.clone().into_sql());
    }
    req.send(row).await?;
    assert_eq!(1, req.finalize().await?.total());

    let row = conn
        .simple_query(format!(
            "SELECT CONVERT(VARBINARY(MAX), c), CONVERT(VARBINARY(MAX), v), \
             CONVERT(VARBINARY(MAX), m), \
             CONVERT(VARBINARY(MAX), CONVERT(VARCHAR(MAX), t)) FROM {table}"
        ))
        .await?
        .into_row()
        .await?
        .unwrap();

    for (i, column) in ["c", "v", "m", "t"].into_iter().enumerate() {
        assert_eq!(
            Some(bytes.as_slice()),
            row.get::<&[u8], _>(i),
            "{collation} column {column}"
        );
    }

    Ok(())
}

#[test_on_runtimes]
async fn bulk_legacy_code_pages_store_every_high_byte<S>(
    mut conn: tiberius::Client<S>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // Detecting a missing `COLLATE` in `INSERT BULK` needs a database default
    // code page other than the columns'.
    let default_code_page = conn
        .query(
            "SELECT CONVERT(INT, COLLATIONPROPERTY(CONVERT(NVARCHAR(128), \
             DATABASEPROPERTYEX(DB_NAME(), 'Collation')), 'CodePage'))",
            &[],
        )
        .await?
        .into_row()
        .await?
        .unwrap()
        .get::<i32, _>(0);

    for (collation, code_page) in [
        ("SQL_Latin1_General_CP437_BIN", 437),
        ("SQL_1xCompat_CP850_CI_AS", 850),
    ] {
        assert_ne!(Some(code_page), default_code_page);

        let table = format!("#{}", random_table().await);
        let result = bulk_every_high_byte_roundtrip(&mut conn, &table, collation).await;
        drop_table(&mut conn, &format!("N'tempdb..{table}'"), &table).await?;
        result?;
    }

    Ok(())
}

#[cfg(all(feature = "tds73", feature = "chrono"))]
test_bulk_type!(datetime2(
    "DATETIME2",
    100,
    vec![DateTime::from_timestamp(1658524194, 123456789); 100].into_iter()
));

#[cfg(all(feature = "tds73", feature = "chrono"))]
test_bulk_type!(datetime2_naive("DATETIME2", 100, {
    #[allow(deprecated)]
    let dt = NaiveDateTime::from_timestamp_opt(1658524194, 123456789).unwrap();

    vec![dt; 100].into_iter()
}));

#[cfg(all(feature = "tds73", feature = "chrono"))]
test_bulk_type!(datetime2_0(
    "DATETIME2(0)",
    100,
    vec![DateTime::from_timestamp(1658524194, 123456789); 100].into_iter()
));

#[cfg(all(feature = "tds73", feature = "chrono"))]
test_bulk_type!(datetime2_1(
    "DATETIME2(1)",
    100,
    vec![DateTime::from_timestamp(1658524194, 123456789); 100].into_iter()
));

#[cfg(all(feature = "tds73", feature = "chrono"))]
test_bulk_type!(datetime2_2(
    "DATETIME2(2)",
    100,
    vec![DateTime::from_timestamp(1658524194, 123456789); 100].into_iter()
));

#[cfg(all(feature = "tds73", feature = "chrono"))]
test_bulk_type!(datetime2_3(
    "DATETIME2(3)",
    100,
    vec![DateTime::from_timestamp(1658524194, 123456789); 100].into_iter()
));

#[cfg(all(feature = "tds73", feature = "chrono"))]
test_bulk_type!(datetime2_4(
    "DATETIME2(4)",
    100,
    vec![DateTime::from_timestamp(1658524194, 123456789); 100].into_iter()
));

#[cfg(all(feature = "tds73", feature = "chrono"))]
test_bulk_type!(datetime2_5(
    "DATETIME2(5)",
    100,
    vec![DateTime::from_timestamp(1658524194, 123456789); 100].into_iter()
));

#[cfg(all(feature = "tds73", feature = "chrono"))]
test_bulk_type!(datetime2_6(
    "DATETIME2(6)",
    100,
    vec![DateTime::from_timestamp(1658524194, 123456789); 100].into_iter()
));

#[cfg(all(feature = "tds73", feature = "chrono"))]
test_bulk_type!(datetime2_7(
    "DATETIME2(7)",
    100,
    vec![DateTime::from_timestamp(1658524194, 123456789); 100].into_iter()
));

#[test_on_runtimes]
async fn read_and_write_to_keyword_columns<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = format!("##{}", random_table().await);

    conn.simple_query(format!("CREATE TABLE {} ([End] INT)", table))
        .await?;

    let mut req = conn.bulk_insert(&table).await.unwrap();
    for num in [6, 7, 8] {
        let mut row = TokenRow::new();
        row.push(ColumnData::I32(Some(num)));
        req.send(row).await.unwrap();
    }
    let result = req.finalize().await.unwrap();
    assert_eq!(result.rows_affected(), &[3]);

    let rows = conn
        .query(format!("SELECT [End] FROM {}", table), &[])
        .await?
        .into_first_result()
        .await?;

    assert_eq!(rows.len(), 3);
    assert_eq!(Some(6), rows[0].get(0));
    assert_eq!(Some(7), rows[1].get(0));
    assert_eq!(Some(8), rows[2].get(0));

    Ok(())
}

macro_rules! test_bulk_columns {
    ($name:ident($total_generated:literal $(, $sql_type:literal)+ $(, ($cols:expr, $generator:expr ))+ $(,)?)) => {
        paste::item! {
            #[test_on_runtimes]
            async fn [< bulk_load_optional_ $name >]<S>(mut conn: tiberius::Client<S>) -> Result<()>
            where
                S: AsyncRead + AsyncWrite + Unpin + Send,
            {
                use tiberius::IntoRow;

                let table = format!("##{}", random_table().await);
                let column_defs = &[$($sql_type,)+];

                conn.execute(
                    &format!(
                        "CREATE TABLE {} (id INT IDENTITY PRIMARY KEY, {})",
                        table,
                        column_defs.join(", "),
                    ),
                    &[],
                )
                    .await?;

                let mut count = 0;

                $(
                    let mut req = conn.bulk_insert_columns(&table, $cols).await?;
                    for i in $generator {
                        let row = i.into_row();
                        req.send(row).await?;
                    }

                    let res = req.finalize().await?;
                    count += res.total();
                )+
                assert_eq!($total_generated, count);

                Ok(())
            }

            #[test_on_runtimes]
            async fn [< bulk_load_required_ $name >]<S>(mut conn: tiberius::Client<S>) -> Result<()>
            where
                S: AsyncRead + AsyncWrite + Unpin + Send,
            {
                use tiberius::IntoRow;
                let table = format!("##{}", random_table().await);
                let column_defs = &[$(format!("{} NOT NULL", $sql_type),)+];

                conn.execute(
                    &format!(
                        "CREATE TABLE {} (id INT IDENTITY PRIMARY KEY, {})",
                        table,
                        column_defs.join(", "),
                    ),
                    &[],
                )
                    .await?;

                let mut count = 0;

                $(
                    let mut req = conn.bulk_insert_columns(&table, $cols).await?;
                    for i in $generator {
                        let row = i.into_row();
                        req.send(row).await?;
                    }

                    let res = req.finalize().await?;
                    count += res.total();
                )+
                assert_eq!($total_generated, count);

                Ok(())
            }

        }
    };
}

test_bulk_columns!(ab_ba_default_columns(
    200,
    "a INT",
    "b FLOAT",
    "c INT DEFAULT 0",
    (&["a", "b"], vec![(1i32, 1f64); 100]),
    (&["b", "a"], vec![(2f64, 2i32); 100]),
));

test_bulk_columns!(ab_ba_override_default_columns(
    200,
    "a INT",
    "b FLOAT",
    "c INT DEFAULT 0",
    (&["a", "b", "c"], vec![(1i32, 1f64, 10i32); 100]),
    (&["b", "c", "a"], vec![(2f64, 20i32, 2i32); 100]),
));

// Server-gated regression for the COLMETADATA `Flags` bit layout (MS-TDS
// §2.2.7.4): the bulk-insert column filter in `src/client.rs` selects only
// columns whose flags report them as `Updateable` and non-`Identity`. If the
// `Identity` or `Computed` bit is misdecoded, an identity/computed column would
// wrongly be treated as a bulk target (or a real target wrongly skipped) and
// the server would reject the row set. This drives a real server to prove the
// flags cause the identity (and computed) columns to be skipped while the
// normal column lands. Compiles locally; runs only with a live server in CI.
#[test_on_runtimes]
async fn bulk_insert_skips_identity_and_computed_columns<S>(
    mut conn: tiberius::Client<S>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = format!("##{}", random_table().await);

    // `id` is IDENTITY (fIdentity set, not writeable), `c` is COMPUTED
    // (fComputed set, not writeable); only `val` is a valid bulk target.
    conn.execute(
        &format!(
            "CREATE TABLE {} (id INT IDENTITY PRIMARY KEY, val INT NOT NULL, c AS (val + 1))",
            table
        ),
        &[],
    )
    .await?;

    let mut req = conn.bulk_insert(&table).await?;
    for v in 0..10i32 {
        let mut row = TokenRow::new();
        row.push(v.into_sql());
        req.send(row).await?;
    }
    let res = req.finalize().await?;
    assert_eq!(10, res.total());

    // All rows landed, identity auto-populated, and the computed column
    // reflects `val + 1` — confirming the identity/computed columns were
    // correctly excluded from the bulk column list.
    let count: i32 = conn
        .query(&format!("SELECT COUNT(*) FROM {}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(10, count);

    let bad: i32 = conn
        .query(
            &format!("SELECT COUNT(*) FROM {} WHERE c <> val + 1", table),
            &[],
        )
        .await?
        .into_row()
        .await?
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(0, bad);

    Ok(())
}

// Server-gated: `KeepIdentity` must let the caller supply explicit identity
// values instead of the server auto-assigning them. It does so by keeping the
// identity column in the bulk column list (there is no `KEEP_IDENTITY` keyword
// in the `INSERT BULK` grammar); without the flag the identity column is
// filtered out and the `id`s would be reassigned. Compiles locally; runs only
// against a live server.
#[test_on_runtimes]
async fn bulk_insert_with_keep_identity_preserves_supplied_ids<S>(
    mut conn: tiberius::Client<S>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use tiberius::{IntoRow, SqlBulkCopyOption};

    let table = format!("##{}", random_table().await);

    conn.execute(
        &format!(
            "CREATE TABLE {} (id INT IDENTITY PRIMARY KEY, val INT NOT NULL)",
            table
        ),
        &[],
    )
    .await?;

    let mut req = conn
        .bulk_insert_with_options(
            &table,
            &["id", "val"],
            SqlBulkCopyOption::KeepIdentity | SqlBulkCopyOption::TableLock,
            &[],
        )
        .await?;

    for (id, val) in [(100i32, 1i32), (200, 2), (300, 3)] {
        req.send((id, val).into_row()).await?;
    }
    let res = req.finalize().await?;
    assert_eq!(3, res.total());

    // The explicit ids survived because the identity column was kept in the
    // bulk column list.
    let kept: i32 = conn
        .query(
            &format!("SELECT COUNT(*) FROM {} WHERE id IN (100, 200, 300)", table),
            &[],
        )
        .await?
        .into_row()
        .await?
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(3, kept);

    Ok(())
}

// Server-gated: an `ORDER (...)` hint plus `TABLOCK` must produce a statement
// the server accepts, and all rows must land. Compiles locally; runs only
// against a live server.
#[test_on_runtimes]
async fn bulk_insert_with_order_hints_inserts_all_rows<S>(
    mut conn: tiberius::Client<S>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use tiberius::{SortOrder, SqlBulkCopyOption};

    let table = format!("##{}", random_table().await);

    conn.execute(
        &format!(
            "CREATE TABLE {} (id INT IDENTITY PRIMARY KEY, val INT NOT NULL)",
            table
        ),
        &[],
    )
    .await?;

    let mut req = conn
        .bulk_insert_with_options(
            &table,
            &["val"],
            SqlBulkCopyOption::TableLock.into(),
            &[("val", SortOrder::Ascending)],
        )
        .await?;

    for v in 0..10i32 {
        let mut row = TokenRow::new();
        row.push(v.into_sql());
        req.send(row).await?;
    }
    let res = req.finalize().await?;
    assert_eq!(10, res.total());

    let count: i32 = conn
        .query(&format!("SELECT COUNT(*) FROM {}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(10, count);

    Ok(())
}

// Server-gated: empty options + empty order hints via the new API must behave
// exactly like `bulk_insert_columns` (no `WITH` clause). Compiles locally; runs
// only against a live server.
#[test_on_runtimes]
async fn bulk_insert_with_options_empty_matches_plain_path<S>(
    mut conn: tiberius::Client<S>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use tiberius::SqlBulkCopyOptions;

    let table = format!("##{}", random_table().await);

    conn.execute(
        &format!(
            "CREATE TABLE {} (id INT IDENTITY PRIMARY KEY, val INT NOT NULL)",
            table
        ),
        &[],
    )
    .await?;

    let mut req = conn
        .bulk_insert_with_options(&table, &["val"], SqlBulkCopyOptions::empty(), &[])
        .await?;

    for v in 0..5i32 {
        let mut row = TokenRow::new();
        row.push(v.into_sql());
        req.send(row).await?;
    }
    let res = req.finalize().await?;
    assert_eq!(5, res.total());

    Ok(())
}
