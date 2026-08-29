use futures_util::io::{AsyncRead, AsyncWrite};
// use futures_util::stream::TryStreamExt;
use names::{Generator, Name};
use once_cell::sync::Lazy;
use std::cell::RefCell;
use std::env;
use std::sync::Once;

use tiberius::{numeric::Numeric, Command, Result, TableValueRow};

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

#[test_on_runtimes]
async fn basic_proc_exec<S>(mut conn: tiberius::Client<S>) -> Result<()>
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

    let mut ins_cmd = Command::new(&proc);
    ins_cmd.bind_param("@Param1", "some text");

    let result = ins_cmd.exec(&mut conn).await?.into_command_result().await?;
    assert_eq!(1, result.return_code());

    let mut ins_cmd = Command::new(&proc);
    ins_cmd.bind_param("@Param1", "another text");

    let result = ins_cmd.exec(&mut conn).await?.into_command_result().await?;
    assert_eq!(2, result.return_code());

    Ok(())
}

struct GeoTest {
    id: i32,
    lat: Numeric,
    lon: Numeric,
}

impl<'a> TableValueRow<'a> for GeoTest {
    fn bind_fields(&self, data_row: &mut tiberius::SqlTableDataRow<'a>) {
        data_row.add_field(self.id);
        data_row.add_field(self.lat);
        data_row.add_field(self.lon);
    }

    fn get_db_type() -> &'static str {
        "GeoTest"
    }
}

#[test_on_runtimes]
async fn tvp_proc_exec<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let table = random_table().await;
    let proc_tvp = random_table().await;
    let proc_ins = random_table().await;
    let proc_get = random_table().await;
    let db_type = random_table().await;

    conn.simple_query(format!(
        r#"
            create type dbo.[{}] as table
            (
                [ID] int not null,
                [lat] decimal(9,6),
                [lon] decimal(9,6)
            )
        "#,
        db_type
    ))
    .await?;

    conn.simple_query(format!(
        r#"
        create table ##{} (
            id int not null,
            lat decimal(9,6),
            lon decimal(9,6),
            n varchar(50)
        )
    "#,
        table
    ))
    .await?;

    conn.simple_query(format!(
        r#"
        create or alter procedure {} 
          @id int,
          @geo dbo.[{}] readonly
        as
        update t set
            [lat] = g.[lat],
            [lon] = g.[lon]
        from
            ##{} t
            inner join @geo g on g.id = t.id

        "#,
        proc_tvp, db_type, table,
    ))
    .await?;

    conn.simple_query(format!(
        r#"
        create or alter procedure {} 
          @id int,
          @name varchar(50)
        as
            insert into ##{} (id, n)
            values (@id, @name)

        "#,
        proc_ins, table,
    ))
    .await?;

    conn.simple_query(format!(
        r#"
        create or alter procedure {} 
          @id int,
          @count int out
        as
          set @count = (select count(*) from ##{})
          select * from ##{}
        "#,
        proc_get, table, table
    ))
    .await?;

    let mut ins_cmd = Command::new(&proc_ins);
    ins_cmd.bind_param("@id", 23);
    ins_cmd.bind_param("@name", "the twenty three");

    let result = ins_cmd.exec(&mut conn).await?.into_command_result().await?;
    assert_eq!(0, result.return_code());

    let g1 = GeoTest {
        id: 23,
        lon: Numeric::new_with_scale(141, 6),
        lat: Numeric::new_with_scale(192, 6),
    };
    let g2 = GeoTest {
        id: 78,
        lon: Numeric::new_with_scale(1141, 6),
        lat: Numeric::new_with_scale(8192, 6),
    };
    let tbl = vec![g1, g2];
    let mut tvp_cmd = Command::new(&proc_tvp);
    tvp_cmd.bind_param("@id", 23);
    tvp_cmd.bind_table_with_dbtype("@geo", &db_type, tbl);

    let result = tvp_cmd.exec(&mut conn).await?.into_command_result().await?;
    assert_eq!(0, result.return_code());

    let count = 0;
    let mut get_cmd = Command::new(&proc_get);
    get_cmd.bind_param("@id", 23);
    get_cmd.bind_out_param("@count", count);

    let result = get_cmd.exec(&mut conn).await?.into_command_result().await?;
    assert_eq!(0, result.return_code());
    let count: i32 = result.try_return_value("@count")?.unwrap();
    assert_eq!(1, count);

    let rows = result.to_query_result(0).unwrap();
    let lat: Numeric = rows[0].get("lat").unwrap();
    let lon: Numeric = rows[0].get("lon").unwrap();
    assert_eq!(Numeric::new_with_scale(141, 6), lon);
    assert_eq!(Numeric::new_with_scale(192, 6), lat);

    Ok(())
}
