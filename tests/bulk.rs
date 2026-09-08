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
    RefCell::new(None);
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

    let value: f64 = conn
        .query(&format!("SELECT content FROM {}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap()
        .get(0)
        .unwrap();

    assert!((value - 1234.5678).abs() < 1e-6, "got {value}");

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
