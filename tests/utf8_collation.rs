use futures_util::io::{AsyncRead, AsyncWrite};
use once_cell::sync::Lazy;
use std::env;
use std::sync::Once;
use tiberius::{IntoSql, Result, TokenRow};

use runtimes_macro::test_on_runtimes;

// This is used in the testing macro :)
#[allow(dead_code)]
static LOGGER_SETUP: Once = Once::new();

static CONN_STR: Lazy<String> = Lazy::new(|| {
    env::var("TIBERIUS_TEST_CONNECTION_STRING").unwrap_or_else(|_| {
        "server=tcp:localhost,1433;IntegratedSecurity=true;TrustServerCertificate=true".to_owned()
    })
});

/// A SQL Server 2019+ `*_UTF8` collation: its `varchar` data is UTF-8.
const UTF8_COLLATION: &str = "Latin1_General_100_CI_AS_SC_UTF8";
const SAMPLE: &str = "中文 café";

/// A `sql_variant` holding a `varchar` with a `*_UTF8` collation is sent as
/// `BigVarChar` with the `fUTF8` collation flag, so its bytes must be decoded
/// as UTF-8 rather than with the LCID's legacy code page.
#[test_on_runtimes]
async fn utf8_collation_sql_variant_decodes_as_utf8<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // The cast to varchar must carry the UTF-8 collation; a plain
    // `CAST(N'...' AS varchar)` would use the database default code page and
    // turn the Chinese characters into `?`.
    let sql = format!(
        "SELECT CAST(CAST(N'{SAMPLE}' COLLATE {UTF8_COLLATION} AS varchar(50)) AS sql_variant)"
    );
    let row = conn.query(sql, &[]).await?.into_row().await?.unwrap();

    assert_eq!(Some(SAMPLE), row.try_get::<&str, _>(0)?);

    Ok(())
}

/// A value written to a `*_UTF8` `varchar` column reads back unchanged.
#[test_on_runtimes]
async fn utf8_collation_temp_table_round_trip<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    conn.simple_query(format!(
        "CREATE TABLE #u8_roundtrip (c varchar(50) COLLATE {UTF8_COLLATION} NULL)"
    ))
    .await?
    .into_results()
    .await?;

    conn.execute("INSERT INTO #u8_roundtrip (c) VALUES (@P1)", &[&SAMPLE])
        .await?;

    let row = conn
        .query("SELECT c FROM #u8_roundtrip", &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(SAMPLE), row.try_get::<&str, _>(0)?);

    Ok(())
}

/// Bulk-inserting non-ASCII text into a `*_UTF8` `varchar` column stores and
/// returns it unchanged.
#[test_on_runtimes]
async fn utf8_collation_bulk_insert_round_trip<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    conn.simple_query(format!(
        "CREATE TABLE #u8_bulk (c varchar(50) COLLATE {UTF8_COLLATION} NULL)"
    ))
    .await?
    .into_results()
    .await?;

    let mut req = conn.bulk_insert("#u8_bulk").await?;
    let mut row = TokenRow::new();
    row.push(SAMPLE.into_sql());
    req.send(row).await?;
    req.finalize().await?;

    let row = conn
        .query("SELECT c FROM #u8_bulk", &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(SAMPLE), row.try_get::<&str, _>(0)?);

    Ok(())
}
