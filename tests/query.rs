use futures_util::io::{AsyncRead, AsyncWrite};
use futures_util::stream::TryStreamExt;
use names::{Generator, Name};
use once_cell::sync::Lazy;
use std::cell::RefCell;
use std::env;
use std::sync::Once;

use tiberius::FromSql;
use tiberius::{numeric::Numeric, xml::XmlData, ColumnType, Query, QueryItem, Result};
use uuid::Uuid;

use runtimes_macro::test_on_runtimes;

// This is used in the testing macro :)
#[allow(dead_code)]
static LOGGER_SETUP: Once = Once::new();

static CONN_STR: Lazy<String> = Lazy::new(|| {
    env::var("TIBERIUS_TEST_CONNECTION_STRING").unwrap_or_else(|_| {
        "server=tcp:localhost,1433;user=SA;password=<YourStrong@Passw0rd>;IntegratedSecurity=true;TrustServerCertificate=true".to_owned()
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

static DOT_CONN_STR: Lazy<String> = Lazy::new(|| CONN_STR.replace("localhost", "."));

static APP_NAME_CONN_STR: Lazy<String> =
    Lazy::new(|| format!("{};Application Name=meow", *CONN_STR));

static ENCRYPTED_CONN_STR: Lazy<String> = Lazy::new(|| format!("{};encrypt=true", *CONN_STR));

static PLAIN_TEXT_CONN_STR: Lazy<String> =
    Lazy::new(|| format!("{};encrypt=DANGER_PLAINTEXT", *CONN_STR));

#[test_on_runtimes(connection_string = "ENCRYPTED_CONN_STR")]
async fn connect_with_full_encryption<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let row = conn
        .query("SELECT @P1", &[&-4i32])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(-4i32), row.get(0));

    Ok(())
}

#[test_on_runtimes(connection_string = "PLAIN_TEXT_CONN_STR")]
async fn connect_as_plain_text<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let row = conn
        .query("SELECT @P1", &[&-4i32])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(-4i32), row.get(0));

    Ok(())
}

#[test_on_runtimes(connection_string = "DOT_CONN_STR")]
async fn connect_dot_server_as_localhost<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let row = conn
        .query("SELECT @P1", &[&-4i32])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(-4i32), row.get(0));

    Ok(())
}

#[test_on_runtimes]
async fn transactions<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    conn.simple_query("BEGIN TRAN").await?;

    let row = conn
        .query("SELECT @P1", &[&-4i32])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(-4i32), row.get(0));

    conn.simple_query("COMMIT").await?;

    Ok(())
}

#[test_on_runtimes]
async fn transactions_300<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    for _ in 1..300 {
        conn.simple_query("BEGIN TRAN").await?;

        let row = conn
            .query("SELECT @P1", &[&-4i32])
            .await?
            .into_row()
            .await?
            .unwrap();

        assert_eq!(Some(-4i32), row.get(0));

        conn.simple_query("COMMIT").await?;
    }

    Ok(())
}

#[test_on_runtimes]
async fn multistatement_query_with_exec_proc<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;
    let proc = random_table().await;

    conn.simple_query(format!(
        r#"
        create table ##{} (
            id int identity(1,1),
            other varchar(50),
        )
    "#,
        table
    ))
    .await?;

    conn.simple_query(format!(
        r#"
        create or alter procedure {} 
          @Param1 varchar(50)
        as
            insert into ##{} (other)
            values (@Param1)

            return scope_identity()
    "#,
        proc, table,
    ))
    .await?;

    let stream = conn
        .query(
            format!(
                "set nocount off; declare @rc int; exec @rc = {} @P1; select @rc as Id;",
                proc
            ),
            &[&"test insert"],
        )
        .await?;

    let row = stream.into_row().await?.unwrap();

    assert_eq!(Some(1), row.get(0));

    let stream = conn
        .query(
            format!(
                "set nocount on; declare @rc int; exec @rc = {} @P1; select @rc as Id;",
                proc
            ),
            &[&"test insert"],
        )
        .await?;

    let row = stream.into_row().await?.unwrap();

    assert_eq!(Some(2), row.get(0));

    Ok(())
}

#[test_on_runtimes]
async fn read_and_write_tinyint<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.execute(format!("CREATE TABLE ##{} (content TINYINT)", table), &[])
        .await?;

    let res = conn
        .execute(
            format!("INSERT INTO ##{} (content) VALUES (@P1), (@P2)", table),
            &[&u8::MIN, &u8::MAX],
        )
        .await?;

    assert_eq!(2, res.total());

    let rows = conn
        .query(format!("SELECT content FROM ##{}", table), &[])
        .await?
        .into_first_result()
        .await?;

    assert_eq!(Some(u8::MIN), rows[0].get(0));
    assert_eq!(Some(u8::MAX), rows[1].get(0));

    Ok(())
}

#[test_on_runtimes]
async fn read_and_write_kanji_varchars<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.execute(
        format!("CREATE TABLE ##{} (content NVARCHAR(max))", table),
        &[],
    )
    .await?;

    let kanji = "余ったものを後で皆に分けようと思っていただけなのに".to_string();
    let long_kanji = "余".repeat(80001);

    let res = conn
        .execute(
            format!("INSERT INTO ##{} (content) VALUES (@P1), (@P2)", table),
            &[&kanji, &long_kanji],
        )
        .await?;

    assert_eq!(2, res.total());

    let rows = conn
        .query(format!("SELECT content FROM ##{}", table), &[])
        .await?
        .into_first_result()
        .await?;

    assert_eq!(Some(kanji.as_str()), rows[0].get(0));
    assert_eq!(Some(long_kanji.as_str()), rows[1].get(0));

    Ok(())
}

#[test_on_runtimes]
async fn read_and_write_weird_garbage<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.execute(
        format!("CREATE TABLE ##{} (content NVARCHAR(1000))", table),
        &[],
    )
    .await?;

    let s = "¥฿😀😁😂😃😄😅😆😇😈😉😊😋😌😍😎😏😐😑😒😓😔😕😖😗😘😙😚😛😜😝😞😟😠😡😢😣😤😥😦😧😨😩😪😫😬😭😮😯😰😱😲😳😴😵😶😷😸😹😺😻😼😽😾😿🙀🙁🙂🙃🙄🙅🙆🙇🙈🙉🙊🙋🙌🙍🙎🙏ऀँंःऄअआइईउऊऋऌऍऎएऐऑऒओऔकखगघङचछजझञटठडढणतथदधनऩपफबभमयर€₭₮₯₰₱₲₳₴₵₶₷₸₹₺₻₼₽₾₿⃀".to_string();

    let res = conn
        .execute(
            format!("INSERT INTO ##{} (content) VALUES (@P1)", table),
            &[&s],
        )
        .await?;

    assert_eq!(1, res.total());

    let rows = conn
        .query(format!("SELECT content FROM ##{}", table), &[])
        .await?
        .into_first_result()
        .await?;

    assert_eq!(Some(s.as_str()), rows[0].get(0));

    Ok(())
}

#[test_on_runtimes]
async fn read_and_write_finnish_varchars<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.execute(
        format!("CREATE TABLE ##{} (content NVARCHAR(max))", table),
        &[],
    )
    .await?;

    let kalevala = "Vaka vanha Väinämöinen / elelevi aikojansa / noilla Väinölän ahoilla, Kalevalan kankahilla.";

    let res = conn
        .execute(
            format!("INSERT INTO ##{} (content) VALUES (@P1)", table),
            &[&kalevala],
        )
        .await?;

    assert_eq!(1, res.total());

    let row = conn
        .query(format!("SELECT content FROM ##{}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(kalevala), row.get(0));

    Ok(())
}

#[test_on_runtimes]
async fn read_and_write_char<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.simple_query(format!("CREATE TABLE ##{} (a char)", table))
        .await?
        .into_results()
        .await?;

    conn.execute(format!("INSERT INTO ##{} (a) values (@P1)", table), &[&"a"])
        .await?;

    let row = conn
        .query(format!("SELECT a FROM ##{}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some("a"), row.get(0));

    Ok(())
}

#[test_on_runtimes]
async fn read_and_write_nchar<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.simple_query(format!("CREATE TABLE ##{} (a nchar)", table))
        .await?
        .into_results()
        .await?;

    conn.execute(format!("INSERT INTO ##{} (a) values (@P1)", table), &[&"ä"])
        .await?;

    let row = conn
        .query(format!("SELECT a FROM ##{}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some("ä"), row.get(0));

    Ok(())
}

#[test_on_runtimes]
async fn execute_insert_update_delete<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.execute(format!("CREATE TABLE ##{} (id int)", table), &[])
        .await?;

    let insert_count = conn
        .execute(
            format!("INSERT INTO ##{} (id) VALUES (@P1), (@P2), (@P3)", table),
            &[&1i32, &2i32, &3i32],
        )
        .await?
        .total();

    assert_eq!(3, insert_count);

    let update_count = conn
        .execute(
            format!("UPDATE ##{} SET id = @P1 WHERE id = @P2", table),
            &[&2i32, &1i32],
        )
        .await?
        .total();

    assert_eq!(1, update_count);

    let delete_count = conn
        .execute(format!("DELETE ##{} WHERE id <> @P1", table), &[&3i32])
        .await?
        .total();

    assert_eq!(2, delete_count);

    Ok(())
}

#[test_on_runtimes]
async fn execute_with_multiple_separate_results<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.execute(format!("CREATE TABLE ##{} (id int)", table), &[])
        .await?;

    let insert_count = conn
        .execute(
            format!("INSERT INTO ##{table} (id) VALUES (@P1); INSERT INTO ##{table} (id) VALUES (@P2), (@P3);", table = table),
            &[&1i32, &2i32, &3i32],
        )
        .await?;

    let result: Vec<_> = insert_count.into_iter().collect();
    assert_eq!(vec![1, 2], result);

    Ok(())
}

#[test_on_runtimes]
async fn execute_multiple_count_total<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.execute(format!("CREATE TABLE ##{} (id int)", table), &[])
        .await?;

    let insert_count = conn
        .execute(
            format!(
                "INSERT INTO ##{table} (id) VALUES (@P1); INSERT INTO ##{table} (id) VALUES (@P2), (@P3);",
                table = table
            ),
            &[&1i32, &2i32, &3i32],
        )
        .await?;

    let result = insert_count.total();
    assert_eq!(3, result);

    Ok(())
}

#[test_on_runtimes]
async fn correct_row_handling_when_not_enough_data<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut stream = conn
        .query(
            "SELECT @P1; SELECT @P2;",
            &[&"a".repeat(4001), &"b".repeat(2095)],
        )
        .await?;

    while let Some(item) = stream.try_next().await? {
        match item {
            QueryItem::Metadata(_) => {
                continue;
            }
            QueryItem::Row(row) if row.result_index() == 0 => {
                assert_eq!(Some("a".repeat(4001).as_str()), row.get(0));
            }
            QueryItem::Row(row) => {
                assert_eq!(Some("b".repeat(2095).as_str()), row.get(0));
            }
        }
    }

    Ok(())
}

#[test_on_runtimes]
async fn multiple_stored_procedure_functions<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let stream = conn.query("EXECUTE sp_executesql N'SELECT 1 UNION ALL SELECT 1 UNION ALL SELECT 1'; EXECUTE sp_executesql N'SELECT 2 UNION ALL SELECT 2'", &[]).await?;

    let rows: Result<Vec<i32>> = stream
        .try_filter_map(|item| async move { Ok(item.into_row()) })
        .map_ok(|row| row.get::<i32, _>(0).unwrap())
        .try_collect()
        .await;

    assert_eq!(rows?, vec![1, 1, 1, 2, 2]);

    Ok(())
}

#[test_on_runtimes]
async fn multiple_queries<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut stream = conn
        .query("SELECT 'a' AS first; SELECT 'b' AS second;", &[])
        .await?;

    while let Some(item) = stream.try_next().await? {
        match item {
            QueryItem::Metadata(meta) if meta.result_index() == 0 => {
                assert_eq!("first", meta.columns()[0].name());
            }
            QueryItem::Row(row) if row.result_index() == 0 => {
                assert_eq!(Some("a"), row.get(0))
            }
            QueryItem::Metadata(meta) => {
                assert_eq!("second", meta.columns()[0].name());
            }
            QueryItem::Row(row) => {
                assert_eq!(Some("b"), row.get(0))
            }
        }
    }

    Ok(())
}

#[test_on_runtimes]
async fn bool_type<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let row = conn
        .query("SELECT @P1, @P2 ORDER BY 1", &[&false, &true])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(false), row.get(0));
    assert_eq!(Some(true), row.get(1));

    Ok(())
}

#[test_on_runtimes]
async fn u8_token<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let row = conn
        .query("SELECT @P1", &[&4u8])
        .await?
        .into_row()
        .await?
        .unwrap();
    assert_eq!(Some(4u8), row.get(0));
    Ok(())
}

#[test_on_runtimes]
async fn i16_token<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let row = conn
        .query("SELECT @P1", &[&-4i16])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(-4i16), row.get(0));

    Ok(())
}

#[test_on_runtimes]
async fn i32_token<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let row = conn
        .query("SELECT @P1", &[&-4i32])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(-4i32), row.get(0));

    Ok(())
}

#[test_on_runtimes]
async fn i64_token<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let row = conn
        .query("SELECT @P1", &[&-4i64])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(-4i64), row.get(0));

    Ok(())
}

#[test_on_runtimes]
async fn f32_token<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let row = conn
        .query("SELECT @P1", &[&4.20f32])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(4.20f32), row.get(0));

    Ok(())
}

#[test_on_runtimes]
async fn f64_token<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let row = conn
        .query("SELECT @P1", &[&4.20f64])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(4.20f64), row.get(0));

    Ok(())
}

#[test_on_runtimes]
async fn read_nullable_u8<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.simple_query(format!("CREATE TABLE ##{} (a tinyint null)", table))
        .await?
        .into_results()
        .await?;

    conn.execute(format!("INSERT INTO ##{} (a) values (null)", table), &[])
        .await?;

    let row = conn
        .query(format!("SELECT a FROM ##{}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    for val in row {
        assert_eq!(&tiberius::ColumnData::U8(None), &val);
        assert_eq!(Option::<u8>::None, u8::from_sql(&val)?)
    }

    Ok(())
}

#[test_on_runtimes]
async fn read_nullable_i16<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.simple_query(format!("CREATE TABLE ##{} (a smallint null)", table))
        .await?
        .into_results()
        .await?;

    conn.execute(format!("INSERT INTO ##{} (a) values (null)", table), &[])
        .await?;

    let row = conn
        .query(format!("SELECT a FROM ##{}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    for val in row {
        assert_eq!(&tiberius::ColumnData::I16(None), &val);
        assert_eq!(Option::<i16>::None, i16::from_sql(&val)?)
    }

    Ok(())
}

#[test_on_runtimes]
async fn read_nullable_i32<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.simple_query(format!("CREATE TABLE ##{} (a int null)", table))
        .await?
        .into_results()
        .await?;

    conn.execute(format!("INSERT INTO ##{} (a) values (null)", table), &[])
        .await?;

    let row = conn
        .query(format!("SELECT a FROM ##{}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    for val in row {
        assert_eq!(&tiberius::ColumnData::I32(None), &val);
        assert_eq!(Option::<i32>::None, i32::from_sql(&val)?)
    }

    Ok(())
}

#[test_on_runtimes]
async fn read_nullable_i64<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.simple_query(format!("CREATE TABLE ##{} (a bigint null)", table))
        .await?
        .into_results()
        .await?;

    conn.execute(format!("INSERT INTO ##{} (a) values (null)", table), &[])
        .await?;

    let row = conn
        .query(format!("SELECT a FROM ##{}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    for val in row {
        assert_eq!(&tiberius::ColumnData::I64(None), &val);
        assert_eq!(Option::<i64>::None, i64::from_sql(&val)?)
    }

    Ok(())
}

#[test_on_runtimes]
async fn read_nullable_f32<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.simple_query(format!("CREATE TABLE ##{} (a real null)", table))
        .await?
        .into_results()
        .await?;

    conn.execute(format!("INSERT INTO ##{} (a) values (null)", table), &[])
        .await?;

    let row = conn
        .query(format!("SELECT a FROM ##{}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    for val in row {
        assert_eq!(Option::<f32>::None, f32::from_sql(&val)?);
        dbg!(&val);
        assert_eq!(tiberius::ColumnData::F32(None), val);
    }

    Ok(())
}

#[test_on_runtimes]
async fn read_nullable_f64<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.simple_query(format!("CREATE TABLE ##{} (a float(25) null)", table))
        .await?
        .into_results()
        .await?;

    conn.execute(format!("INSERT INTO ##{} (a) values (null)", table), &[])
        .await?;

    let row = conn
        .query(format!("SELECT a FROM ##{}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    for val in row {
        assert_eq!(&tiberius::ColumnData::F64(None), &val);
        assert_eq!(Option::<f64>::None, f64::from_sql(&val)?)
    }

    Ok(())
}

#[test_on_runtimes]
async fn short_strings<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let s = "Hallo";

    let row = conn
        .query("SELECT @P1", &[&s])
        .await?
        .into_row()
        .await?
        .unwrap();
    assert_eq!(Some(s), row.get::<&str, _>(0));

    Ok(())
}

#[test_on_runtimes]
async fn long_strings<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let string = "a".repeat(4001);

    let row = conn
        .query("SELECT @P1", &[&string.as_str()])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(string.as_str()), row.get(0));
    Ok(())
}

#[test_on_runtimes]
async fn stored_procedures<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let rows = conn
        .query(
            "EXECUTE sp_executesql N'SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3'",
            &[],
        )
        .await?
        .into_first_result()
        .await?;

    assert_eq!(Some(1), rows[0].get(0));
    assert_eq!(Some(2), rows[1].get(0));
    assert_eq!(Some(3), rows[2].get(0));

    Ok(())
}

#[test_on_runtimes]
async fn drop_stream_before_handling_all_results_should_not_cause_weird_things<S>(
    mut conn: tiberius::Client<S>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    {
        let mut stream = conn
            .query(
                "SELECT @P1; SELECT @P2;",
                &[&"a".repeat(8000), &"b".repeat(8001)],
            )
            .await?;

        while let Some(item) = stream.try_next().await? {
            if let QueryItem::Row(row) = item {
                assert_eq!(Some("a".repeat(8000).as_str()), row.get(0));
                break;
            }
        }
    }

    {
        let row = conn
            .query("SELECT @P1", &[&1i32])
            .await?
            .into_row()
            .await?
            .unwrap();
        assert_eq!(Some(1i32), row.get(0));
    }

    Ok(())
}

#[test_on_runtimes]
async fn floats_in_nbc_rows<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.simple_query(format!(
        r#"
        create table ##{} (
            id int identity(1,1),
            col1 float(53) null,
            col2 float(53) null,
            col3 float(53) null,
            col4 float(53) null,
            col5 float(53) null,
            col6 float(53) null,
            col7 float(53) null,
            col8 float(53) null
        )
    "#,
        table
    ))
    .await?;

    conn.execute(
        format!(
            "INSERT INTO ##{} (col1, col2, col3, col4, col5, col6, col7, col8) VALUES (@P1, @P2, @P3, @P4, @P5, @P6, @P7, @P8)",
            table
        ),
        &[
            &Option::<f64>::None,
            &Option::<f64>::None,
            &Option::<f64>::Some(1.23f64),
            &Option::<f64>::None,
            &Option::<f64>::None,
            &Option::<f64>::None,
            &Option::<f64>::None,
            &Option::<f64>::None
        ],
    ).await?;

    let mut stream = conn
        .query(
            &format!(
                "SELECT col1, col2, col3, col4, col5, col6, col7, col8 FROM ##{}",
                table
            ),
            &[],
        )
        .await?;

    let expected_results = vec![None, None, Some(1.23f64), None, None, None, None];

    let mut res: Vec<Option<f64>> = Vec::new();

    while let Some(item) = stream.try_next().await? {
        if let QueryItem::Row(row) = item {
            for i in 0..expected_results.len() {
                res.push(row.get(i))
            }
        }
    }

    assert_eq!(expected_results, res);

    Ok(())
}

#[test_on_runtimes]
async fn tinyint_in_nbc_rows<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.simple_query(format!(
        r#"
        create table ##{} (
            id int identity(1,1),
            col1 tinyint null,
            col2 tinyint null,
            col3 tinyint null,
            col4 tinyint null,
            col5 tinyint null,
            col6 tinyint null,
            col7 tinyint null,
            col8 tinyint null
        )
    "#,
        table
    ))
    .await?;

    conn.execute(
        format!(
            "INSERT INTO ##{} (col1, col2, col3, col4, col5, col6, col7, col8) VALUES (@P1, @P2, @P3, @P4, @P5, @P6, @P7, @P8)",
            table
        ),
        &[
            &Option::<u8>::None,
            &Option::<u8>::None,
            &Option::<u8>::Some(1u8),
            &Option::<u8>::None,
            &Option::<u8>::None,
            &Option::<u8>::None,
            &Option::<u8>::None,
            &Option::<u8>::None
        ],
    ).await?;

    let mut stream = conn
        .query(
            &format!(
                "SELECT col1, col2, col3, col4, col5, col6, col7, col8 FROM ##{}",
                table
            ),
            &[],
        )
        .await?;

    let expected_results = vec![None, None, Some(1u8), None, None, None, None];

    let mut res: Vec<Option<u8>> = Vec::new();

    while let Some(item) = stream.try_next().await? {
        if let QueryItem::Row(row) = item {
            for i in 0..expected_results.len() {
                res.push(row.get(i))
            }
        }
    }

    assert_eq!(expected_results, res);

    Ok(())
}

#[test_on_runtimes]
async fn smallint_in_nbc_rows<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.simple_query(format!(
        r#"
        create table ##{} (
            id int identity(1,1),
            col1 smallint null,
            col2 smallint null,
            col3 smallint null,
            col4 smallint null,
            col5 smallint null,
            col6 smallint null,
            col7 smallint null,
            col8 smallint null
        )
    "#,
        table
    ))
    .await?;

    conn.execute(
        format!(
            "INSERT INTO ##{} (col1, col2, col3, col4, col5, col6, col7, col8) VALUES (@P1, @P2, @P3, @P4, @P5, @P6, @P7, @P8)",
            table
        ),
        &[
            &Option::<i16>::None,
            &Option::<i16>::None,
            &Option::<i16>::Some(1i16),
            &Option::<i16>::None,
            &Option::<i16>::None,
            &Option::<i16>::None,
            &Option::<i16>::None,
            &Option::<i16>::None
        ],
    ).await?;

    let mut stream = conn
        .query(
            &format!(
                "SELECT col1, col2, col3, col4, col5, col6, col7, col8 FROM ##{}",
                table
            ),
            &[],
        )
        .await?;

    let expected_results = vec![None, None, Some(1i16), None, None, None, None];

    let mut res: Vec<Option<i16>> = Vec::new();

    while let Some(item) = stream.try_next().await? {
        if let QueryItem::Row(row) = item {
            for i in 0..expected_results.len() {
                res.push(row.get(i))
            }
        }
    }

    assert_eq!(expected_results, res);

    Ok(())
}

#[test_on_runtimes]
async fn int_in_nbc_rows<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.simple_query(format!(
        r#"
        create table ##{} (
            id int identity(1,1),
            col1 int null,
            col2 int null,
            col3 int null,
            col4 int null,
            col5 int null,
            col6 int null,
            col7 int null,
            col8 int null
        )
    "#,
        table
    ))
    .await?;

    conn.execute(
        format!(
            "INSERT INTO ##{} (col1, col2, col3, col4, col5, col6, col7, col8) VALUES (@P1, @P2, @P3, @P4, @P5, @P6, @P7, @P8)",
            table
        ),
        &[
            &Option::<i32>::None,
            &Option::<i32>::None,
            &Option::<i32>::Some(1i32),
            &Option::<i32>::None,
            &Option::<i32>::None,
            &Option::<i32>::None,
            &Option::<i32>::None,
            &Option::<i32>::None
        ],
    ).await?;

    let mut stream = conn
        .query(
            &format!(
                "SELECT col1, col2, col3, col4, col5, col6, col7, col8 FROM ##{}",
                table
            ),
            &[],
        )
        .await?;

    let expected_results = vec![None, None, Some(1i32), None, None, None, None];

    let mut res: Vec<Option<i32>> = Vec::new();

    while let Some(item) = stream.try_next().await? {
        if let QueryItem::Row(row) = item {
            for i in 0..expected_results.len() {
                res.push(row.get(i))
            }
        }
    }

    assert_eq!(expected_results, res);

    Ok(())
}

#[test_on_runtimes]
async fn bigint_in_nbc_rows<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.simple_query(format!(
        r#"
        create table ##{} (
            id int identity(1,1),
            col1 bigint null,
            col2 bigint null,
            col3 bigint null,
            col4 bigint null,
            col5 bigint null,
            col6 bigint null,
            col7 bigint null,
            col8 bigint null
        )
    "#,
        table
    ))
    .await?;

    conn.execute(
        format!(
            "INSERT INTO ##{} (col1, col2, col3, col4, col5, col6, col7, col8) VALUES (@P1, @P2, @P3, @P4, @P5, @P6, @P7, @P8)",
            table
        ),
        &[
            &Option::<i64>::None,
            &Option::<i64>::None,
            &Option::<i64>::Some(1i64),
            &Option::<i64>::None,
            &Option::<i64>::None,
            &Option::<i64>::None,
            &Option::<i64>::None,
            &Option::<i64>::None
        ],
    ).await?;

    let mut stream = conn
        .query(
            &format!(
                "SELECT col1, col2, col3, col4, col5, col6, col7, col8 FROM ##{}",
                table
            ),
            &[],
        )
        .await?;

    let expected_results = vec![None, None, Some(1i64), None, None, None, None];

    let mut res: Vec<Option<i64>> = Vec::new();

    while let Some(item) = stream.try_next().await? {
        if let QueryItem::Row(row) = item {
            for i in 0..expected_results.len() {
                res.push(row.get(i))
            }
        }
    }

    assert_eq!(expected_results, res);

    Ok(())
}

#[test_on_runtimes]
async fn nbc_rows<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut stream = conn
        .query(
            "SELECT NULL, NULL, NULL, NULL, 1, NULL, NULL, NULL, 2, NULL, NULL, 3, NULL, 4",
            &[],
        )
        .await?;

    let expected_results = vec![
        None,
        None,
        None,
        None,
        Some(1),
        None,
        None,
        None,
        Some(2),
        None,
        None,
        Some(3),
        None,
        Some(4),
    ];

    let mut res: Vec<Option<i32>> = Vec::new();

    while let Some(item) = stream.try_next().await? {
        if let QueryItem::Row(row) = item {
            for i in 0..expected_results.len() {
                res.push(row.get(i))
            }
        }
    }

    assert_eq!(expected_results, res);

    Ok(())
}

#[test_on_runtimes]
async fn ntext_type<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    let string = r#"Hääpuhetta voi värittää kertomalla vitsejä, aforismeja,
        sananlaskuja, laulunsäkeitä ja muita lainauksia. Huumori sopii hääpuheeseen,
        mutta vitsit eivät saa loukata. Häissä ensimmäisen juhlapuheen pitää
        perinteisesti morsiamen isä."#;

    conn.execute(format!("CREATE TABLE ##{} (content NTEXT)", table), &[])
        .await?;

    conn.execute(
        format!("INSERT INTO ##{} (content) VALUES (@P1)", table),
        &[&string],
    )
    .await?;

    let row = conn
        .query(format!("SELECT content FROM ##{}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(string), row.get::<&str, _>(0));

    Ok(())
}

#[test_on_runtimes]
async fn ntext_empty<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.execute(format!("CREATE TABLE ##{} (content NTEXT)", table), &[])
        .await?;

    conn.execute(
        format!("INSERT INTO ##{} (content) VALUES (@P1)", table),
        &[&Option::<String>::None],
    )
    .await?;

    let row = conn
        .query(format!("SELECT content FROM ##{}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(None, row.get::<&str, _>(0));

    Ok(())
}

#[test_on_runtimes]
async fn text_type<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;
    let string = "a".repeat(10000);

    conn.execute(format!("CREATE TABLE ##{} (content TEXT)", table), &[])
        .await?;

    conn.execute(
        format!("INSERT INTO ##{} (content) VALUES (@P1)", table),
        &[&string.as_str()],
    )
    .await?;

    let row = conn
        .query(format!("SELECT content FROM ##{}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(string.as_str()), row.get(0));

    Ok(())
}

#[test_on_runtimes]
async fn varchar_empty<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.execute(
        format!("CREATE TABLE ##{} (content NVARCHAR(max))", table),
        &[],
    )
    .await?;

    conn.execute(
        format!("INSERT INTO ##{} (content) VALUES (@P1)", table),
        &[&Option::<String>::None],
    )
    .await?;

    let row = conn
        .query(format!("SELECT content FROM ##{}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(None, row.get::<&str, _>(0));

    Ok(())
}

#[test_on_runtimes]
async fn text_empty<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.execute(format!("CREATE TABLE ##{} (content TEXT)", table), &[])
        .await?;

    conn.execute(
        format!("INSERT INTO ##{} (content) VALUES (@P1)", table),
        &[&Option::<String>::None],
    )
    .await?;

    let row = conn
        .query(format!("SELECT content FROM ##{}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(None, row.get::<&str, _>(0));

    Ok(())
}

#[test_on_runtimes]
async fn varbinary_empty<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.execute(
        format!("CREATE TABLE ##{} (content VARBINARY(max))", table),
        &[],
    )
    .await?;

    let total = conn
        .execute(
            format!("INSERT INTO ##{} (content) VALUES (@P1)", table),
            &[&Option::<Vec<u8>>::None],
        )
        .await?
        .total();

    assert_eq!(1, total);

    let row = conn
        .query(format!("SELECT content FROM ##{}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(None, row.get::<&[u8], _>(0));

    Ok(())
}

#[test_on_runtimes]
async fn binary_type<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.execute(
        format!("CREATE TABLE ##{} (content BINARY(8000))", table),
        &[],
    )
    .await?;

    let mut binary = vec![0; 7999];
    binary.push(5);

    let inserted = conn
        .execute(
            format!("INSERT INTO ##{} (content) VALUES (@P1)", table),
            &[&binary.as_slice()],
        )
        .await?
        .total();

    assert_eq!(1, inserted);

    let row = conn
        .query(format!("SELECT content FROM ##{}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    let result: &[u8] = row.get(0).unwrap();

    assert_eq!(8000, result.len());
    assert_eq!(binary.as_slice(), result);

    Ok(())
}

#[test_on_runtimes]
async fn varbinary_type<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.execute(
        format!("CREATE TABLE ##{} (content VARBINARY(8000))", table),
        &[],
    )
    .await?;

    let mut binary = vec![0; 79];
    binary.push(5);

    let inserted = conn
        .execute(
            format!("INSERT INTO ##{} (content) VALUES (@P1)", table),
            &[&binary.as_slice()],
        )
        .await?
        .total();

    assert_eq!(1, inserted);

    let row = conn
        .query(format!("SELECT content FROM ##{}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    let result: &[u8] = row.get(0).unwrap();

    assert_eq!(80, result.len());
    assert_eq!(binary, result);

    Ok(())
}

#[test_on_runtimes]
async fn image_type<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.execute(format!("CREATE TABLE ##{} (content IMAGE)", table), &[])
        .await?;

    let mut binary = vec![0; 79];
    binary.push(5);

    let inserted = conn
        .execute(
            format!("INSERT INTO ##{} (content) VALUES (@P1)", table),
            &[&binary.as_slice()],
        )
        .await?
        .total();

    assert_eq!(1, inserted);

    let row = conn
        .query(format!("SELECT content FROM ##{}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    let result: &[u8] = row.get(0).unwrap();

    assert_eq!("content", row.columns()[0].name());
    assert_eq!(80, result.len());
    assert_eq!(binary, result);

    Ok(())
}

#[test_on_runtimes]
async fn guid_type_roundtrip<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let id = Uuid::new_v4();
    let row = conn
        .query("SELECT @P1", &[&id])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(id), row.get(0));

    Ok(())
}

#[test_on_runtimes]
async fn guid_type_byte_ordering<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let id = Uuid::parse_str("c97dbc01-fb45-4384-a194-e39a4560cf4a").unwrap();
    let row = conn
        .simple_query("SELECT CAST('c97dbc01-fb45-4384-a194-e39a4560cf4a' AS UNIQUEIDENTIFIER)")
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(id), row.get(0));

    Ok(())
}

#[test_on_runtimes]
async fn varbinary_max<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.execute(
        format!("CREATE TABLE ##{} (content VARBINARY(max))", table),
        &[],
    )
    .await?;

    let mut binary = vec![0; 8000];
    binary.push(5);

    let inserted = conn
        .execute(
            format!("INSERT INTO ##{} (content) VALUES (@P1)", table),
            &[&binary.as_slice()],
        )
        .await?
        .total();

    assert_eq!(1, inserted);

    let row = conn
        .query(format!("SELECT content FROM ##{}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    let result: &[u8] = row.get(0).unwrap();

    assert_eq!(8001, result.len());
    assert_eq!(binary, result);

    Ok(())
}

#[test_on_runtimes]
async fn numeric_type_u32_presentation<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let num = Numeric::new_with_scale(2, 1);

    let row = conn
        .query("SELECT @P1", &[&num])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(num), row.get(0));

    Ok(())
}

#[test_on_runtimes]
async fn numeric_type_u64_presentation<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let num = Numeric::new_with_scale(std::i32::MAX as i128 + 10, 1);

    let row = conn
        .query("SELECT @P1", &[&num])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(num), row.get(0));

    Ok(())
}

#[test_on_runtimes]
async fn numeric_type_u96_presentation<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let num = Numeric::new_with_scale(std::i64::MAX as i128, 19);

    let row = conn
        .query("SELECT @P1", &[&num])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(num), row.get(0));

    Ok(())
}

#[test_on_runtimes]
async fn numeric_type_u128_presentation<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let num = Numeric::new_with_scale(std::i64::MAX as i128, 37);

    let row = conn
        .query("SELECT @P1", &[&num])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(num), row.get(0));

    Ok(())
}

#[cfg(feature = "rust_decimal")]
#[cfg(test)]
mod rust_decimal {
    use super::*;

    #[test_on_runtimes]
    async fn decimal_type_u32_presentation<S>(mut conn: tiberius::Client<S>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        use tiberius::numeric::Decimal;

        let num = Decimal::from_i128_with_scale(2, 1);
        let row = conn
            .query("SELECT @P1", &[&num])
            .await?
            .into_row()
            .await?
            .unwrap();

        assert_eq!(Some(num), row.get(0));

        Ok(())
    }

    #[test_on_runtimes]
    async fn decimal_type_u64_presentation<S>(mut conn: tiberius::Client<S>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        use tiberius::numeric::Decimal;

        let num = Decimal::from_i128_with_scale(i32::MAX as i128 + 10, 1);
        let row = conn
            .query("SELECT @P1 AS foo", &[&num])
            .await?
            .into_row()
            .await?
            .unwrap();

        assert_eq!(Some(num), row.get("foo"));

        Ok(())
    }

    #[test_on_runtimes]
    async fn decimal_type_u96_presentation<S>(mut conn: tiberius::Client<S>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        use tiberius::numeric::Decimal;

        let num = Decimal::from_i128_with_scale(i64::MAX as i128, 19);
        let row = conn
            .query("SELECT @P1", &[&num])
            .await?
            .into_row()
            .await?
            .unwrap();

        assert_eq!(Some(num), row.get(0));

        Ok(())
    }

    #[test_on_runtimes]
    async fn decimal_type_u128_presentation<S>(mut conn: tiberius::Client<S>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        use tiberius::numeric::Decimal;

        let num = Decimal::from_i128_with_scale(i64::MAX as i128, 28);
        let row = conn
            .query("SELECT @P1", &[&num])
            .await?
            .into_row()
            .await?
            .unwrap();

        assert_eq!(Some(num), row.get(0));

        Ok(())
    }
}

#[cfg(feature = "bigdecimal")]
#[cfg(test)]
mod bigdecimal {
    use super::*;

    #[test_on_runtimes]
    async fn bigdecimal_type_u32_presentation<S>(mut conn: tiberius::Client<S>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        use std::str::FromStr;
        use tiberius::numeric::BigDecimal;

        let num = BigDecimal::from_str("2").unwrap();
        let row = conn
            .query("SELECT @P1", &[&num])
            .await?
            .into_row()
            .await?
            .unwrap();

        assert_eq!(Some(num), row.get(0));

        Ok(())
    }

    #[test_on_runtimes]
    async fn handles_scale_underflow_with_bigdecimal<S>(mut conn: tiberius::Client<S>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        use bigdecimal_::num_bigint::BigInt;
        use num_traits::FromPrimitive;
        use tiberius::numeric::BigDecimal;

        let int = BigInt::from_i128(90).unwrap();
        let num = BigDecimal::new(int, -1);

        let row = conn
            .query("SELECT @P1", &[&num])
            .await?
            .into_row()
            .await?
            .unwrap();

        assert_eq!(Some(num), row.get(0));

        Ok(())
    }

    #[test_on_runtimes]
    async fn bigdecimal_type_u64_presentation<S>(mut conn: tiberius::Client<S>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        use bigdecimal_::num_bigint::BigInt;
        use num_traits::FromPrimitive;
        use tiberius::numeric::BigDecimal;

        let int = BigInt::from_i128(i32::MAX as i128 + 10).unwrap();
        let num = BigDecimal::new(int, 1);

        let row = conn
            .query("SELECT @P1 AS foo", &[&num])
            .await?
            .into_row()
            .await?
            .unwrap();

        assert_eq!(Some(num), row.get("foo"));

        Ok(())
    }

    #[test_on_runtimes]
    async fn bigdecimal_type_u96_presentation<S>(mut conn: tiberius::Client<S>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        use bigdecimal_::num_bigint::BigInt;
        use num_traits::FromPrimitive;
        use tiberius::numeric::BigDecimal;

        let int = BigInt::from_i128(i64::MAX as i128 + 10).unwrap();
        let num = BigDecimal::new(int, 19);

        let row = conn
            .query("SELECT @P1", &[&num])
            .await?
            .into_row()
            .await?
            .unwrap();

        assert_eq!(Some(num), row.get(0));

        Ok(())
    }

    #[test_on_runtimes]
    async fn bigdecimal_type_u128_presentation<S>(mut conn: tiberius::Client<S>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        use bigdecimal_::num_bigint::BigInt;
        use num_traits::FromPrimitive;
        use tiberius::numeric::BigDecimal;

        let int = BigInt::from_i128(i64::MAX as i128).unwrap();
        let num = BigDecimal::new(int, 28);

        let row = conn
            .query("SELECT @P1", &[&num])
            .await?
            .into_row()
            .await?
            .unwrap();

        assert_eq!(Some(num), row.get(0));

        Ok(())
    }

    #[test_on_runtimes]
    async fn dynamic_query_binding_bigdecimal<S>(mut conn: tiberius::Client<S>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        use bigdecimal_::num_bigint::BigInt;
        use num_traits::FromPrimitive;
        use tiberius::numeric::BigDecimal;

        let int = BigInt::from_i128(i64::MAX as i128).unwrap();
        let num = BigDecimal::new(int, 28);
        let mut query = Query::new("SELECT @P1, @P2");

        query.bind(num.clone());
        query.bind(Option::<BigDecimal>::None);

        let row = query.query(&mut conn).await?.into_row().await?.unwrap();

        assert_eq!(Some(num), row.get(0));
        assert_eq!(Option::<BigDecimal>::None, row.get(1));

        Ok(())
    }
}

#[cfg(all(not(feature = "tds73"), feature = "chrono"))]
#[test_on_runtimes]
async fn naive_date_time_tds72<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use chrono::NaiveDate;

    let dt = NaiveDate::from_ymd_opt(2020, 4, 20)
        .unwrap()
        .and_hms_opt(16, 20, 0)
        .unwrap();

    let stream = conn.query("SELECT @P1", &[&dt]).await?;
    let row = stream.into_row().await?.unwrap();

    assert_eq!(Some(dt), row.get(0));

    Ok(())
}

#[cfg(all(feature = "tds73", feature = "chrono"))]
#[test_on_runtimes]
async fn naive_small_date_time_tds73<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use chrono::NaiveDate;

    let dt = NaiveDate::from_ymd_opt(2020, 4, 20)
        .unwrap()
        .and_hms_opt(16, 20, 0)
        .unwrap();
    let table = random_table().await;

    conn.execute(
        format!("CREATE TABLE ##{} (date smalldatetime)", table),
        &[],
    )
    .await?;

    conn.execute(
        format!("INSERT INTO ##{} (date) VALUES (@P1)", table),
        &[&dt],
    )
    .await?
    .total();

    let row = conn
        .query(format!("SELECT date FROM ##{}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(dt), row.get(0));
    Ok(())
}

#[cfg(all(feature = "tds73", feature = "chrono"))]
#[test_on_runtimes]
async fn naive_date_time2_tds73<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use chrono::NaiveDate;

    let dt = NaiveDate::from_ymd_opt(2020, 4, 20)
        .unwrap()
        .and_hms_opt(16, 20, 0)
        .unwrap();

    let table = random_table().await;

    conn.execute(format!("CREATE TABLE ##{} (date datetime2)", table), &[])
        .await?;

    conn.execute(
        format!("INSERT INTO ##{} (date) VALUES (@P1)", table),
        &[&dt],
    )
    .await?
    .total();

    let row = conn
        .query(format!("SELECT date FROM ##{}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(dt), row.get(0));
    Ok(())
}

#[cfg(all(feature = "tds73", feature = "chrono"))]
#[test_on_runtimes]
async fn datetime_as_datetime2_tds73<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let dt = chrono::DateTime::parse_from_rfc3339("2020-02-27T19:10:00Z").unwrap();
    let table = random_table().await;

    conn.execute(format!("CREATE TABLE ##{} (date datetime2)", table), &[])
        .await?;

    conn.execute(
        format!("INSERT INTO ##{} (date) VALUES (@P1)", table),
        &[&dt],
    )
    .await?
    .total();

    let row = conn
        .query(format!("SELECT date FROM ##{}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(dt.naive_utc()), row.get(0));
    Ok(())
}

#[cfg(all(feature = "tds73", feature = "chrono"))]
#[test_on_runtimes]
async fn naive_time<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use chrono::NaiveTime;

    let time = NaiveTime::from_hms_opt(16, 20, 0).unwrap();

    let row = conn
        .query("SELECT @P1", &[&time])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(time), row.get(0));

    let mut query = Query::new("SELECT @P1, @P2");

    query.bind(time);
    query.bind(Option::<NaiveTime>::None);

    let stream = query.query(&mut conn).await?;
    let row = stream.into_row().await?.unwrap();

    assert_eq!(Some(time), row.get(0));
    assert_eq!(Option::<NaiveTime>::None, row.get(1));

    Ok(())
}

#[cfg(all(feature = "tds73", feature = "chrono"))]
#[test_on_runtimes]
async fn naive_date<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use chrono::NaiveDate;

    let date = NaiveDate::from_ymd_opt(2020, 4, 20).unwrap();

    let row = conn
        .query("SELECT @P1", &[&date])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(date), row.get(0));

    let mut query = Query::new("SELECT @P1, @P2");

    query.bind(date);
    query.bind(Option::<NaiveDate>::None);

    let stream = query.query(&mut conn).await?;
    let row = stream.into_row().await?.unwrap();

    assert_eq!(Some(date), row.get(0));
    assert_eq!(Option::<NaiveDate>::None, row.get(1));

    Ok(())
}

#[cfg(all(feature = "tds73", feature = "chrono"))]
#[test_on_runtimes]
async fn date_time_utc<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use chrono::{offset::Utc, DateTime, NaiveDate};

    let naive = NaiveDate::from_ymd_opt(2020, 4, 20)
        .unwrap()
        .and_hms_opt(16, 20, 0)
        .unwrap();
    let dt: DateTime<Utc> = DateTime::from_naive_utc_and_offset(naive, Utc);

    let row = conn
        .query("SELECT @P1", &[&dt])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(dt), row.get(0));

    let mut query = Query::new("SELECT @P1, @P2");

    query.bind(dt);
    query.bind(Option::<DateTime<Utc>>::None);

    let stream = query.query(&mut conn).await?;
    let row = stream.into_row().await?.unwrap();

    assert_eq!(Some(dt), row.get(0));
    assert_eq!(Option::<DateTime<Utc>>::None, row.get(1));

    Ok(())
}

#[cfg(all(feature = "tds73", feature = "chrono"))]
#[test_on_runtimes]
async fn date_time_fixed<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use chrono::{offset::FixedOffset, DateTime, NaiveDate};

    let naive = NaiveDate::from_ymd_opt(2020, 4, 20)
        .unwrap()
        .and_hms_opt(16, 20, 0)
        .unwrap();

    let fixed = FixedOffset::east_opt(3600 * 3).unwrap();
    let dt: DateTime<FixedOffset> = DateTime::from_naive_utc_and_offset(naive, fixed);

    let row = conn
        .query("SELECT @P1", &[&dt])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(dt), row.get(0));

    let mut query = Query::new("SELECT @P1, @P2");

    query.bind(dt);
    query.bind(Option::<DateTime<FixedOffset>>::None);

    let stream = query.query(&mut conn).await?;
    let row = stream.into_row().await?.unwrap();

    assert_eq!(Some(dt), row.get(0));
    assert_eq!(Option::<DateTime<FixedOffset>>::None, row.get(1));

    Ok(())
}

#[cfg(all(feature = "tds73", feature = "chrono"))]
#[test_on_runtimes]
async fn date_time_fixed_convertion<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use chrono::{offset::FixedOffset, DateTime, NaiveDate};

    let naive = NaiveDate::from_ymd_opt(2020, 4, 20)
        .unwrap()
        .and_hms_opt(16, 20, 0)
        .unwrap();
    let fixed = FixedOffset::east_opt(3600 * 3).unwrap();
    let dt: DateTime<FixedOffset> = DateTime::from_naive_utc_and_offset(naive, fixed);

    let row = conn
        .query(format!("SELECT CAST('{}' AS datetimeoffset(7))", dt), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(dt), row.get(0));

    Ok(())
}

// time crate

#[cfg(all(not(feature = "tds73"), feature = "time"))]
#[test_on_runtimes]
async fn primitive_date_time_tds72_time_crate<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let dt = time::Date::from_calendar_date(2020, time::Month::April, 20)
        .unwrap()
        .with_hms(16, 20, 0)
        .unwrap();

    let stream = conn.query("SELECT @P1", &[&dt]).await?;
    let row = stream.into_row().await?.unwrap();

    assert_eq!(Some(dt), row.get(0));

    Ok(())
}

#[cfg(all(feature = "tds73", feature = "time"))]
#[test_on_runtimes]
async fn primitive_small_date_time_tds73_time_crate<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let dt = time::Date::from_calendar_date(2020, time::Month::April, 20)
        .unwrap()
        .with_hms(16, 20, 0)
        .unwrap();

    let table = random_table().await;

    conn.execute(
        format!("CREATE TABLE ##{} (date smalldatetime)", table),
        &[],
    )
    .await?;

    conn.execute(
        format!("INSERT INTO ##{} (date) VALUES (@P1)", table),
        &[&dt],
    )
    .await?
    .total();

    let row = conn
        .query(format!("SELECT date FROM ##{}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(dt), row.get(0));
    Ok(())
}

#[cfg(all(feature = "tds73", feature = "time"))]
#[test_on_runtimes]
async fn primitive_date_time2_tds73_time_crate<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let dt = time::Date::from_calendar_date(2020, time::Month::April, 20)
        .unwrap()
        .with_hms(16, 20, 0)
        .unwrap();
    let table = random_table().await;

    conn.execute(format!("CREATE TABLE ##{} (date datetime2)", table), &[])
        .await?;

    conn.execute(
        format!("INSERT INTO ##{} (date) VALUES (@P1)", table),
        &[&dt],
    )
    .await?
    .total();

    let row = conn
        .query(format!("SELECT date FROM ##{}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(dt), row.get(0));
    Ok(())
}

#[cfg(all(feature = "tds73", feature = "time"))]
#[test_on_runtimes]
async fn time_with_time_crate<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let time = time::Time::from_hms(16, 20, 0).unwrap();

    let row = conn
        .query("SELECT @P1", &[&time])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(time), row.get(0));

    Ok(())
}

#[cfg(all(feature = "tds73", feature = "time"))]
#[test_on_runtimes]
async fn date_with_time_crate<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let date = time::Date::from_calendar_date(2020, time::Month::April, 20).unwrap();

    let row = conn
        .query("SELECT @P1", &[&date])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(date), row.get(0));

    Ok(())
}

#[cfg(all(feature = "tds73", feature = "time"))]
#[test_on_runtimes]
async fn offset_datetime_utc_with_time_crate<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let dt = time::Date::from_calendar_date(2020, time::Month::April, 20)
        .unwrap()
        .with_hms(16, 20, 00)
        .unwrap()
        .assume_offset(time::UtcOffset::UTC);

    let row = conn
        .query("SELECT @P1", &[&dt])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(dt), row.get(0));

    Ok(())
}

#[cfg(all(feature = "tds73", feature = "time"))]
#[test_on_runtimes]
async fn offset_date_time_fixed_with_time_crate<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let dt = time::Date::from_calendar_date(2020, time::Month::April, 20)
        .unwrap()
        .with_hms(16, 20, 00)
        .unwrap()
        .assume_offset(time::UtcOffset::from_hms(3, 0, 0).unwrap());

    let row = conn
        .query("SELECT @P1", &[&dt])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(dt), row.get(0));

    Ok(())
}

#[cfg(all(feature = "tds73", feature = "time"))]
#[test_on_runtimes]
async fn offset_date_time_fixed_with_time_crate_conversion<S>(
    mut conn: tiberius::Client<S>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use time::format_description::well_known::Rfc3339;

    let dt = time::Date::from_calendar_date(2020, time::Month::April, 20)
        .unwrap()
        .with_hms(16, 20, 00)
        .unwrap()
        .assume_offset(time::UtcOffset::from_hms(3, 0, 0).unwrap());

    let row = conn
        .query(
            format!(
                "SELECT CAST('{}' AS datetimeoffset(7))",
                dt.format(&Rfc3339).unwrap()
            ),
            &[&dt],
        )
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(dt), row.get(0));

    Ok(())
}

#[test_on_runtimes]
async fn xml_read_write<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let xml = XmlData::new("<root><child attr=\"attr-value\"/></root>");
    let row = conn
        .query("SELECT @P1", &[&xml])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(&xml), row.get(0));

    Ok(())
}

#[test_on_runtimes]
async fn xml_read_null_xml<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let row = conn
        .query("SELECT CAST(NULL AS XML)", &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(None, row.get::<&XmlData, _>(0));

    Ok(())
}

#[test_on_runtimes]
async fn money_smallmoney<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.execute(
        format!(
            "CREATE TABLE ##{} (m1 Money NOT NULL, m2 SmallMoney NOT NULL, m3 Money, m4 SmallMoney)",
            table
        ),
        &[],
    )
    .await?;

    let res = conn
        .execute(
            format!(
                "INSERT INTO ##{} (m1, m2, m3, m4) VALUES (@P1, @P2, @P3, @P4)",
                table
            ),
            &[&1.23, &2.33, &4.56, &5.67],
        )
        .await?;

    assert_eq!(1, res.total());

    let row = conn
        .query(format!("SELECT m1, m2, m3, m4 FROM ##{}", table), &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some(1.23), row.get(0));
    assert_eq!(Some(2.33), row.get(1));
    assert_eq!(Some(4.56), row.get(2));
    assert_eq!(Some(5.67), row.get(3));

    Ok(())
}

#[test_on_runtimes]
async fn mars_sp_routines_must_fetch_all_results<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let q = r#"
        DECLARE @SQL NVARCHAR(MAX) = N''
        SELECT @SQL += N'ALTER TABLE '
            + QUOTENAME(OBJECT_SCHEMA_NAME(PARENT_OBJECT_ID))
            + '.'
            + QUOTENAME(OBJECT_NAME(PARENT_OBJECT_ID))
            + ' DROP CONSTRAINT '
            + OBJECT_NAME(OBJECT_ID) + ';'
        FROM SYS.OBJECTS
        WHERE TYPE_DESC LIKE '%CONSTRAINT'
            AND TYPE_DESC <> 'FOREIGN_KEY_CONSTRAINT'
            AND OBJECT_NAME(PARENT_OBJECT_ID) = 'Post'
            AND SCHEMA_NAME(SCHEMA_ID) = 'making_an_existing_id_field_autoincrement_works_with_foreign_keys'
        EXEC sp_execute @SQL
    "#;

    let res = conn.simple_query(q).await;

    assert!(res.is_err());

    Ok(())
}

#[test_on_runtimes]
async fn warnings_should_not_affect_column_fetch<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let proc = random_table().await;

    let q = format!(
        r#"
        CREATE PROCEDURE {}
        AS
        BEGIN
            SET NOCOUNT ON;
            DECLARE @tmp TABLE (col int);
            INSERT INTO @tmp
            SELECT SUM(col) AS col FROM (SELECT NULL AS col UNION SELECT 1) t;
            SELECT SUM(col) AS col FROM @tmp;
        END
    "#,
        proc
    );

    conn.simple_query(&q).await?;

    let mut rs = conn.simple_query(format!("EXEC {}", proc)).await?;

    while let Some(item) = rs.try_next().await? {
        if let QueryItem::Metadata(meta) = item {
            let col = meta.columns().first();

            assert_eq!(Some("col"), col.map(|c| c.name()));
            assert_eq!(Some(ColumnType::Int4), col.map(|c| c.column_type()));
        }
    }

    Ok(())
}

#[test_on_runtimes]
async fn cyrillic_collations_should_work<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    conn.simple_query(
        "CREATE TABLE #cyrillic_test (
            single CHAR(1)       COLLATE Cyrillic_General_CI_AS,
            multi  VARCHAR(255)  COLLATE Cyrillic_General_CI_AS,
            huge   TEXT          COLLATE Cyrillic_General_CI_AS
        )",
    )
    .await?;

    conn.execute(
        "INSERT INTO #cyrillic_test (single, multi, huge) VALUES (@P1, @P2, @P3)",
        &[
            &"Ж",
            &"В Советском Союзе попытки борьбы с пьянством предпринимались не единожды. Первая антиалкогольная",
            &"Первая антиалкогольная",
        ],
    )
    .await?;

    let row = conn
        .query("SELECT single, multi, huge FROM #cyrillic_test", &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some("Ж"), row.get(0));
    assert_eq!(
        Some("В Советском Союзе попытки борьбы с пьянством предпринимались не единожды. Первая антиалкогольная"),
        row.get(1)
    );
    assert_eq!(Some("Первая антиалкогольная"), row.get(2));

    Ok(())
}

#[test_on_runtimes(connection_string = "APP_NAME_CONN_STR")]
async fn application_name_should_be_set_correctly<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let row = conn
        .query("SELECT APP_NAME()", &[])
        .await?
        .into_row()
        .await?
        .unwrap();

    assert_eq!(Some("meow"), row.get(0));

    Ok(())
}

#[test_on_runtimes]
async fn columns_fetch_should_work<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut stream = conn
        .query("SELECT @P1 AS first; SELECT @P2 AS second", &[&1i32, &2i32])
        .await?;

    // Nothing is fetched, the first result set starts.
    let cols = stream.columns().await?.unwrap();
    assert_eq!("first", cols[0].name());

    // Move over the metadata.
    stream.try_next().await?;

    // We're in the first row, seeing the metadata for that set.
    let cols = stream.columns().await?.unwrap();
    assert_eq!("first", cols[0].name());

    // Move over the only row in the first set.
    stream.try_next().await?;

    // End of the first set, getting the metadata by peaking the next item.
    let cols = stream.columns().await?.unwrap();
    assert_eq!("second", cols[0].name());

    Ok(())
}

#[test_on_runtimes]
async fn into_row_stream_should_work<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let stream = conn
        .query("SELECT @P1 AS first; SELECT @P2 AS second", &[&1i32, &2i32])
        .await?;

    let mut stream = stream.into_row_stream();

    let row = stream.try_next().await?.unwrap();
    assert_eq!(Some(1), row.get(0));

    let row = stream.try_next().await?.unwrap();
    assert_eq!(Some(2), row.get(0));

    Ok(())
}

#[test_on_runtimes]
async fn dynamic_query_binding_strings<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let data = String::from("foo");
    let mut query =
        Query::new("SELECT @P1, @P2, @P3, @P4, @P5, @P6, @P7, @P8, @P9, @P10, @P11, @P12");

    query.bind(&data);
    query.bind(Some(&data));
    query.bind(Option::<&String>::None);

    query.bind(data.as_str());
    query.bind(Some(data.as_str()));
    query.bind(Option::<&str>::None);

    query.bind("foo");
    query.bind(Some("foo"));
    query.bind(Option::<&'static str>::None);

    query.bind(String::from("foo"));
    query.bind(Some(String::from("foo")));
    query.bind(Option::<String>::None);

    let mut stream = query.query(&mut conn).await?.into_row_stream();

    let row = stream.try_next().await?.unwrap();

    assert_eq!(Some("foo"), row.get(0));
    assert_eq!(Some("foo"), row.get(1));
    assert_eq!(Option::<&str>::None, row.get(2));

    assert_eq!(Some("foo"), row.get(3));
    assert_eq!(Some("foo"), row.get(4));
    assert_eq!(Option::<&str>::None, row.get(5));

    assert_eq!(Some("foo"), row.get(6));
    assert_eq!(Some("foo"), row.get(7));
    assert_eq!(Option::<&str>::None, row.get(8));

    assert_eq!(Some("foo"), row.get(9));
    assert_eq!(Some("foo"), row.get(10));
    assert_eq!(Option::<&str>::None, row.get(11));

    Ok(())
}

#[test_on_runtimes]
async fn dynamic_query_binding_bytes<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let data = vec![1u8, 6u8, 2u8, 0u8];
    let mut query = Query::new("SELECT @P1, @P2, @P3, @P4, @P5, @P6");

    query.bind(&data);
    query.bind(Option::<&Vec<u8>>::None);
    query.bind(data.as_slice());
    query.bind(Option::<&[u8]>::None);
    query.bind(data.clone());
    query.bind(Option::<Vec<u8>>::None);

    let mut stream = query.query(&mut conn).await?.into_row_stream();

    let row = stream.try_next().await?.unwrap();

    assert_eq!(Some(data.as_slice()), row.get(0));
    assert_eq!(Option::<&[u8]>::None, row.get(1));
    assert_eq!(Some(data.as_slice()), row.get(2));
    assert_eq!(Option::<&[u8]>::None, row.get(3));
    assert_eq!(Some(data.as_slice()), row.get(4));
    assert_eq!(Option::<&[u8]>::None, row.get(5));

    Ok(())
}

#[test_on_runtimes]
async fn dynamic_query_binding_xml<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let data = XmlData::new("<foo>lol</foo>");
    let mut query = Query::new("SELECT @P1, @P2, @P3, @P4");

    query.bind(&data);
    query.bind(data.clone());
    query.bind(Option::<&XmlData>::None);
    query.bind(Option::<XmlData>::None);

    let mut stream = query.query(&mut conn).await?.into_row_stream();

    let row = stream.try_next().await?.unwrap();

    assert_eq!(Some(&data), row.get(0));
    assert_eq!(Some(&data), row.get(1));
    assert_eq!(Option::<&XmlData>::None, row.get(2));
    assert_eq!(Option::<&XmlData>::None, row.get(3));

    Ok(())
}

#[test_on_runtimes]
async fn dynamic_query_binding_guid<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let data = Uuid::new_v4();
    let mut query = Query::new("SELECT @P1, @P2, @P3, @P4");

    query.bind(data);
    query.bind(data);
    query.bind(Option::<&Uuid>::None);
    query.bind(Option::<Uuid>::None);

    let mut stream = query.query(&mut conn).await?.into_row_stream();

    let row = stream.try_next().await?.unwrap();

    assert_eq!(Some(data), row.get(0));
    assert_eq!(Some(data), row.get(1));
    assert_eq!(Option::<Uuid>::None, row.get(2));
    assert_eq!(Option::<Uuid>::None, row.get(3));

    Ok(())
}

#[test_on_runtimes]
async fn dynamic_query_binding_numbers<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut query =
        Query::new("SELECT @P1, @P2, @P3, @P4, @P5, @P6, @P7, @P8, @P9, @P10, @P11, @P12");

    query.bind(1u8);
    query.bind(1i16);
    query.bind(1i32);
    query.bind(1i64);
    query.bind(std::f32::consts::PI);
    query.bind(std::f64::consts::PI);

    query.bind(Option::<u8>::None);
    query.bind(Option::<i16>::None);
    query.bind(Option::<i32>::None);
    query.bind(Option::<i64>::None);
    query.bind(Option::<f32>::None);
    query.bind(Option::<f64>::None);

    let mut stream = query.query(&mut conn).await?.into_row_stream();

    let row = stream.try_next().await?.unwrap();

    assert_eq!(Some(1u8), row.get(0));
    assert_eq!(Some(1i16), row.get(1));
    assert_eq!(Some(1i32), row.get(2));
    assert_eq!(Some(1i64), row.get(3));
    assert_eq!(Some(std::f32::consts::PI), row.get(4));
    assert_eq!(Some(std::f64::consts::PI), row.get(5));

    assert_eq!(Option::<u8>::None, row.get(6));
    assert_eq!(Option::<i16>::None, row.get(7));
    assert_eq!(Option::<i32>::None, row.get(8));
    assert_eq!(Option::<i64>::None, row.get(9));
    assert_eq!(Option::<f32>::None, row.get(10));
    assert_eq!(Option::<f64>::None, row.get(11));

    Ok(())
}

#[test_on_runtimes]
async fn dynamic_query_binding_boolean<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut query = Query::new("SELECT @P1, @P2");

    query.bind(true);
    query.bind(Option::<bool>::None);

    let mut stream = query.query(&mut conn).await?.into_row_stream();

    let row = stream.try_next().await?.unwrap();

    assert_eq!(Some(true), row.get(0));
    assert_eq!(Option::<bool>::None, row.get(1));

    Ok(())
}

#[test_on_runtimes]
async fn new_execute_interface<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;

    conn.execute(
        format!("CREATE TABLE ##{} (m1 NVARCHAR(255) NOT NULL)", table),
        &[],
    )
    .await?;

    let data = String::from("foo");
    let mut query = Query::new(format!("INSERT INTO ##{} (m1) VALUES (@P1)", table));
    query.bind(&data);

    let res = query.execute(&mut conn).await?;
    assert_eq!(1, res.total());

    Ok(())
}
