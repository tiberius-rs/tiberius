//! Integration tests for `Client::cancel_query`: after a cancel, the next
//! requests on the connection must get their own responses.

use futures_util::future::{self, Either};
use futures_util::io::{AsyncRead, AsyncWrite};
use futures_util::TryStreamExt;
use once_cell::sync::Lazy;
use std::env;
use std::sync::Once;
use std::time::Duration;

use runtimes_macro::test_on_runtimes;
use tiberius::{QueryItem, Result};

// This is used in the testing macro :)
#[allow(dead_code)]
static LOGGER_SETUP: Once = Once::new();

static CONN_STR: Lazy<String> = Lazy::new(|| {
    env::var("TIBERIUS_TEST_CONNECTION_STRING").unwrap_or_else(|_| {
        "server=tcp:localhost,1433;user=SA;password=<YourStrong@Passw0rd>;IntegratedSecurity=true;TrustServerCertificate=true".to_owned()
    })
});

async fn select<S>(conn: &mut tiberius::Client<S>, n: i32) -> Result<Option<i32>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let row = conn
        .simple_query(format!("SELECT {n}"))
        .await?
        .into_row()
        .await?;
    Ok(row.and_then(|r| r.get::<i32, _>(0)))
}

async fn in_step<S>(conn: &mut tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    assert_eq!(Some(1), select(conn, 1).await?);
    assert_eq!(Some(2), select(conn, 2).await?);
    Ok(())
}

// Nothing comes back before the cancel. The server ends the cancelled
// response and then acknowledges the cancel in a message of its own.
#[test_on_runtimes]
async fn cancel_while_the_server_waits<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    {
        let query = conn.simple_query("WAITFOR DELAY '00:00:30'");
        let delay = futures_timer::Delay::new(Duration::from_millis(300));
        futures_util::pin_mut!(query);
        match future::select(query, delay).await {
            Either::Left((res, _)) => panic!("the query finished first: {:?}", res.is_ok()),
            Either::Right(_) => (),
        }
    }
    conn.cancel_query().await?;
    in_step(&mut conn).await
}

// Rows arrive before the server starts waiting, and the stream is dropped
// with some of them unread.
#[test_on_runtimes]
async fn cancel_after_reading_some_rows<S>(mut conn: tiberius::Client<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    {
        let mut stream = conn
            .simple_query("SELECT name FROM sys.all_objects WAITFOR DELAY '00:00:30'")
            .await?;
        loop {
            match stream.try_next().await? {
                Some(QueryItem::Row(_)) => break,
                Some(_) => (),
                None => panic!("no rows"),
            }
        }
    }
    conn.cancel_query().await?;
    in_step(&mut conn).await
}
