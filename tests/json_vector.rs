//! Integration tests for the SQL Server 2025 `json` and `vector` types.
//!
//! These need SQL Server 2025 (major version 17) or later and skip themselves
//! on older servers. They use `TIBERIUS_TEST_CONNECTION_STRING` like the other
//! integration tests.

use std::env;

use futures_util::stream::TryStreamExt;
use once_cell::sync::Lazy;
use tiberius::{vector::Vector, Client, ColumnType, Config, IntoSql, Result, TokenRow};
use tokio::net::TcpStream;
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};

static CONN_STR: Lazy<String> = Lazy::new(|| {
    env::var("TIBERIUS_TEST_CONNECTION_STRING").unwrap_or_else(|_| {
        "server=tcp:localhost,1433;user=SA;password=<YourStrong@Passw0rd>;IntegratedSecurity=true;TrustServerCertificate=true".to_owned()
    })
});

type TestClient = Client<Compat<TcpStream>>;

/// Connects with the given feature requests. Returns `None` (and the test
/// passes vacuously) when the server predates SQL Server 2025.
async fn connect(json: bool, vector: bool) -> Result<Option<TestClient>> {
    let mut config = Config::from_ado_string(&CONN_STR)?;
    config.json_support(json);
    config.vector_support(vector);

    let tcp = TcpStream::connect(config.get_addr()).await?;
    tcp.set_nodelay(true)?;
    let mut client = Client::connect(config, tcp.compat_write()).await?;

    let major: i32 = client
        .simple_query("SELECT CAST(SERVERPROPERTY('ProductMajorVersion') AS int)")
        .await?
        .into_row()
        .await?
        .and_then(|row| row.get(0))
        .unwrap_or(0);

    if major < 17 {
        eprintln!("skipping: json/vector need SQL Server 2025, server major version is {major}");
        return Ok(None);
    }

    Ok(Some(client))
}

fn v(values: &[f32]) -> Vector {
    Vector::from(values)
}

#[tokio::test]
async fn native_json_column_is_read_as_string() -> Result<()> {
    let Some(mut conn) = connect(true, false).await? else {
        return Ok(());
    };

    conn.simple_query("CREATE TABLE #j (id int IDENTITY PRIMARY KEY, doc json NULL)")
        .await?
        .into_results()
        .await?;

    let doc = r#"{"name":"ação","tags":[1,2,3]}"#;
    conn.execute("INSERT INTO #j (doc) VALUES (@P1), (NULL)", &[&doc])
        .await?;

    let rows = conn
        .simple_query("SELECT doc FROM #j ORDER BY id")
        .await?
        .into_first_result()
        .await?;

    assert_eq!(rows[0].columns()[0].column_type(), ColumnType::Json);
    assert_eq!(rows[0].get::<&str, _>(0), Some(doc));
    assert_eq!(rows[1].get::<&str, _>(0), None);

    // Expressions of type json are native too.
    let row = conn
        .simple_query("SELECT JSON_OBJECT('k': 'v'), JSON_ARRAY(1, 2)")
        .await?
        .into_row()
        .await?
        .unwrap();
    assert_eq!(row.get::<&str, _>(0), Some(r#"{"k":"v"}"#));
    assert_eq!(row.get::<&str, _>(1), Some("[1,2]"));

    Ok(())
}

#[tokio::test]
async fn large_json_spans_packets() -> Result<()> {
    let Some(mut conn) = connect(true, false).await? else {
        return Ok(());
    };

    // ~200 KB: many TDS packets and well past any USHORTLEN limit.
    let items: Vec<String> = (0..20_000).map(|i| format!("\"item{i}\"")).collect();
    let doc = format!("[{}]", items.join(","));

    let row = conn
        .query("SELECT CAST(@P1 AS json)", &[&doc.as_str()])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(row.columns()[0].column_type(), ColumnType::Json);
    assert_eq!(row.get::<&str, _>(0), Some(doc.as_str()));

    Ok(())
}

#[tokio::test]
async fn without_json_support_json_is_nvarchar() -> Result<()> {
    let Some(mut conn) = connect(false, false).await? else {
        return Ok(());
    };

    let row = conn
        .simple_query("SELECT CAST('{\"a\":1}' AS json)")
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(row.columns()[0].column_type(), ColumnType::NVarchar);
    assert_eq!(row.get::<&str, _>(0), Some(r#"{"a":1}"#));

    Ok(())
}

#[tokio::test]
async fn native_vector_column_and_parameters() -> Result<()> {
    let Some(mut conn) = connect(false, true).await? else {
        return Ok(());
    };

    conn.simple_query("CREATE TABLE #v (id int IDENTITY PRIMARY KEY, emb vector(3) NULL)")
        .await?
        .into_results()
        .await?;

    let a = v(&[0.1, 0.2, 0.3]);
    let none: Option<Vector> = None;
    conn.execute("INSERT INTO #v (emb) VALUES (@P1), (@P2)", &[&a, &none])
        .await?;
    // A JSON-array string still converts implicitly.
    conn.execute("INSERT INTO #v (emb) VALUES (@P1)", &[&"[1, 2, 3]"])
        .await?;

    let rows = conn
        .simple_query("SELECT emb FROM #v ORDER BY id")
        .await?
        .into_first_result()
        .await?;

    assert_eq!(rows[0].columns()[0].column_type(), ColumnType::Vector);
    assert_eq!(rows[0].get::<&Vector, _>(0), Some(&a));
    assert_eq!(rows[1].get::<&Vector, _>(0), None);
    assert_eq!(rows[2].get::<Vector, _>(0), Some(v(&[1.0, 2.0, 3.0])));

    // A native vector parameter takes part in vector functions.
    let row = conn
        .query(
            "SELECT VECTOR_DISTANCE('euclidean', emb, @P1) FROM #v WHERE id = 3",
            &[&v(&[1.0, 2.0, 5.0])],
        )
        .await?
        .into_row()
        .await?
        .unwrap();
    assert_eq!(row.get::<f64, _>(0), Some(2.0));

    // Round trip through a parameter.
    let row = conn
        .query("SELECT @P1", &[&v(&[4.5, -6.25])])
        .await?
        .into_row()
        .await?
        .unwrap();
    assert_eq!(row.columns()[0].column_type(), ColumnType::Vector);
    assert_eq!(row.get::<Vector, _>(0), Some(v(&[4.5, -6.25])));

    Ok(())
}

#[tokio::test]
async fn native_vector_max_dimensions() -> Result<()> {
    let Some(mut conn) = connect(false, true).await? else {
        return Ok(());
    };

    let big: Vec<f32> = (0..1998).map(|i| i as f32 / 7.0).collect();
    let row = conn
        .query(
            "SELECT CAST(@P1 AS vector(1998))",
            &[&Vector::from(big.clone())],
        )
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(row.get::<Vector, _>(0).map(Vector::into_vec), Some(big));

    Ok(())
}

#[tokio::test]
async fn without_vector_support_vectors_are_text() -> Result<()> {
    let Some(mut conn) = connect(false, false).await? else {
        return Ok(());
    };

    conn.simple_query("CREATE TABLE #v (id int IDENTITY PRIMARY KEY, emb vector(2) NULL)")
        .await?
        .into_results()
        .await?;

    // Vector parameters fall back to JSON-array text.
    let none: Option<Vector> = None;
    conn.execute(
        "INSERT INTO #v (emb) VALUES (@P1), (@P2)",
        &[&v(&[0.5, 1.5]), &none],
    )
    .await?;

    let rows = conn
        .simple_query("SELECT emb FROM #v ORDER BY id")
        .await?
        .into_first_result()
        .await?;

    // The server sends varchar(max) JSON text; `Vector` parses it.
    assert!(matches!(
        rows[0].columns()[0].column_type(),
        ColumnType::NVarchar | ColumnType::BigVarChar
    ));
    assert_eq!(rows[0].get::<Vector, _>(0), Some(v(&[0.5, 1.5])));
    assert!(rows[0].get::<&str, _>(0).unwrap().starts_with('['));
    assert_eq!(rows[1].get::<Vector, _>(0), None);

    Ok(())
}

#[tokio::test]
async fn bulk_insert_native_json_and_vector() -> Result<()> {
    let Some(mut conn) = connect(true, true).await? else {
        return Ok(());
    };

    conn.simple_query(
        "CREATE TABLE ##tib_bulk_jv (id int IDENTITY PRIMARY KEY, doc json NULL, emb vector(2) NULL)",
    )
    .await?
    .into_results()
    .await?;

    let mut req = conn.bulk_insert("##tib_bulk_jv").await?;

    let mut row = TokenRow::new();
    row.push(r#"{"n":1}"#.into_sql());
    row.push(v(&[1.0, 2.0]).into_sql());
    req.send(row).await?;

    let mut row = TokenRow::new();
    row.push(Option::<&str>::None.into_sql());
    row.push(Option::<&Vector>::None.into_sql());
    req.send(row).await?;

    assert_eq!(req.finalize().await?.total(), 2);

    let rows: Vec<_> = conn
        .simple_query("SELECT doc, emb FROM ##tib_bulk_jv ORDER BY id")
        .await?
        .into_row_stream()
        .try_collect()
        .await?;

    assert_eq!(rows[0].get::<&str, _>(0), Some(r#"{"n":1}"#));
    assert_eq!(rows[0].get::<&Vector, _>(1), Some(&v(&[1.0, 2.0])));
    assert_eq!(rows[1].get::<&str, _>(0), None);
    assert_eq!(rows[1].get::<&Vector, _>(1), None);

    conn.simple_query("DROP TABLE ##tib_bulk_jv")
        .await?
        .into_results()
        .await?;

    Ok(())
}

#[tokio::test]
async fn bulk_insert_vector_without_native_support() -> Result<()> {
    let Some(mut conn) = connect(false, false).await? else {
        return Ok(());
    };

    conn.simple_query(
        "CREATE TABLE ##tib_bulk_v_text (id int IDENTITY PRIMARY KEY, emb vector(2) NULL)",
    )
    .await?
    .into_results()
    .await?;

    let mut req = conn.bulk_insert("##tib_bulk_v_text").await?;
    let mut row = TokenRow::new();
    row.push(v(&[3.0, 4.0]).into_sql());
    req.send(row).await?;
    assert_eq!(req.finalize().await?.total(), 1);

    let row = conn
        .simple_query("SELECT emb FROM ##tib_bulk_v_text")
        .await?
        .into_row()
        .await?
        .unwrap();
    assert_eq!(row.get::<Vector, _>(0), Some(v(&[3.0, 4.0])));

    conn.simple_query("DROP TABLE ##tib_bulk_v_text")
        .await?
        .into_results()
        .await?;

    Ok(())
}

#[tokio::test]
async fn bulk_insert_rejects_wrong_vector_dimensions() -> Result<()> {
    let Some(mut conn) = connect(false, true).await? else {
        return Ok(());
    };

    conn.simple_query(
        "CREATE TABLE ##tib_bulk_v_dims (id int IDENTITY PRIMARY KEY, emb vector(2))",
    )
    .await?
    .into_results()
    .await?;

    let mut req = conn.bulk_insert("##tib_bulk_v_dims").await?;
    let mut row = TokenRow::new();
    row.push(v(&[1.0, 2.0, 3.0]).into_sql());
    let err = req
        .send(row)
        .await
        .expect_err("3 elements into vector(2) must fail");
    assert!(
        matches!(err, tiberius::error::Error::BulkInput(_)),
        "{err:?}"
    );

    Ok(())
}
