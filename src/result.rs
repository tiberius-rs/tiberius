pub use crate::tds::stream::{CommandItem, QueryItem, ResultMetadata};
use crate::{
    client::Connection,
    error::Error,
    tds::stream::{CommandReturnValue, ReceivedToken, TokenStream},
    FromSql, Row,
};
use futures_util::io::{AsyncRead, AsyncWrite};
use futures_util::stream::TryStreamExt;
use std::fmt::Debug;

/// A result from a query execution, listing the number of affected rows.
///
/// If executing multiple queries, the resulting counts will be come separately,
/// marking the rows affected for each query.
///
/// # Example
///
/// ```no_run
/// # use tiberius::Config;
/// # use tokio_util::compat::TokioAsyncWriteCompatExt;
/// # use std::env;
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let c_str = env::var("TIBERIUS_TEST_CONNECTION_STRING").unwrap_or(
/// #     "server=tcp:localhost,1433;integratedSecurity=true;TrustServerCertificate=true".to_owned(),
/// # );
/// # let config = Config::from_ado_string(&c_str)?;
/// # let tcp = tokio::net::TcpStream::connect(config.get_addr()).await?;
/// # tcp.set_nodelay(true)?;
/// # let mut client = tiberius::Client::connect(config, tcp.compat_write()).await?;
/// let result = client
///     .execute(
///         "INSERT INTO #Test (id) VALUES (@P1); INSERT INTO #Test (id) VALUES (@P2, @P3)",
///         &[&1i32, &2i32, &3i32],
///     )
///     .await?;
///
/// assert_eq!(&[1, 2], result.rows_affected());
/// # Ok(())
/// # }
/// ```
///
/// [`Client`]: struct.Client.html
/// [`Rows`]: struct.Row.html
/// [`next_resultset`]: #method.next_resultset
#[derive(Debug)]
pub struct ExecuteResult {
    rows_affected: Vec<u64>,
}

impl<'a> ExecuteResult {
    pub(crate) async fn new<S: AsyncRead + AsyncWrite + Unpin + Send>(
        connection: &'a mut Connection<S>,
    ) -> crate::Result<Self> {
        let mut token_stream = TokenStream::new(connection).try_unfold();
        let mut rows_affected = Vec::new();

        while let Some(token) = token_stream.try_next().await? {
            match token {
                ReceivedToken::DoneProc(done) if done.is_final() => (),
                ReceivedToken::DoneProc(done) => rows_affected.push(done.rows()),
                ReceivedToken::DoneInProc(done) => rows_affected.push(done.rows()),
                ReceivedToken::Done(done) => rows_affected.push(done.rows()),
                _ => (),
            }
        }

        Ok(Self { rows_affected })
    }

    /// A slice of numbers of rows affected in the same order as the given
    /// queries.
    pub fn rows_affected(&self) -> &[u64] {
        self.rows_affected.as_slice()
    }

    /// Aggregates all resulting row counts into a sum.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tiberius::Config;
    /// # use tokio_util::compat::TokioAsyncWriteCompatExt;
    /// # use std::env;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let c_str = env::var("TIBERIUS_TEST_CONNECTION_STRING").unwrap_or(
    /// #     "server=tcp:localhost,1433;integratedSecurity=true;TrustServerCertificate=true".to_owned(),
    /// # );
    /// # let config = Config::from_ado_string(&c_str)?;
    /// # let tcp = tokio::net::TcpStream::connect(config.get_addr()).await?;
    /// # tcp.set_nodelay(true)?;
    /// # let mut client = tiberius::Client::connect(config, tcp.compat_write()).await?;
    /// let rows_affected = client
    ///     .execute(
    ///         "INSERT INTO #Test (id) VALUES (@P1); INSERT INTO #Test (id) VALUES (@P2, @P3)",
    ///         &[&1i32, &2i32, &3i32],
    ///     )
    ///     .await?;
    ///
    /// assert_eq!(3, rows_affected.total());
    /// # Ok(())
    /// # }
    pub fn total(self) -> u64 {
        self.rows_affected.into_iter().sum()
    }
}

impl IntoIterator for ExecuteResult {
    type Item = u64;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.rows_affected.into_iter()
    }
}

/// A materialized result from executing a [`Command`], carrying the number of
/// affected rows, the return code, the values of any OUT parameters and any
/// record sets returned by the command.
///
/// [`Command`]: crate::Command
///
/// # Example
///
/// ```no_run
/// # use tiberius::{Config, Command};
/// # use tokio_util::compat::TokioAsyncWriteCompatExt;
/// # use std::env;
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let c_str = env::var("TIBERIUS_TEST_CONNECTION_STRING").unwrap_or(
/// #     "server=tcp:localhost,1433;integratedSecurity=true;TrustServerCertificate=true".to_owned(),
/// # );
/// # let config = Config::from_ado_string(&c_str)?;
/// # let tcp = tokio::net::TcpStream::connect(config.get_addr()).await?;
/// # tcp.set_nodelay(true)?;
/// # let mut client = tiberius::Client::connect(config, tcp.compat_write()).await?;
/// let mut cmd = Command::new("dbo.usp_SomeStoredProc");
///
/// cmd.bind_param("@foo", 34i32);
/// cmd.bind_out_param("@bar", "bar");
/// let res = cmd.exec(&mut client).await?.into_command_result().await?;
///
/// let rv: Option<&str> = res.try_return_value("@bar")?;
/// let rc = res.return_code();
/// let ra = res.rows_affected();
///
/// let rs0 = res.to_query_result(0);
/// # Ok(())
/// # }
/// ```
///
#[derive(Debug)]
pub struct CommandResult {
    pub(crate) rows_affected: Vec<u64>,
    pub(crate) return_code: u32,
    pub(crate) return_values: Vec<CommandReturnValue>,
    pub(crate) query_results: Vec<Vec<Row>>,
}

impl<'a> CommandResult {
    /// A slice of the numbers of rows affected, in the same order as the
    /// statements ran by the command.
    pub fn rows_affected(&self) -> &[u64] {
        self.rows_affected.as_slice()
    }

    /// The return code of the command, as returned by the server.
    pub fn return_code(&self) -> u32 {
        self.return_code
    }

    /// The number of returned values (OUT parameters) available.
    pub fn return_values_len(&self) -> usize {
        self.return_values.len()
    }

    /// Gets a returned value by its OUT parameter name, converting it to `T`.
    /// Returns `None` if the value is `NULL`, and an error if no OUT parameter
    /// with the given name was returned.
    pub fn try_return_value<T>(&'a self, name: &str) -> crate::Result<Option<T>>
    where
        T: FromSql<'a>,
    {
        let col_data = self
            .return_values
            .iter()
            .find(|p| p.name.eq(name))
            .ok_or_else(|| {
                Error::Conversion(format!("Could not find return value {}", name).into())
            })?;

        T::from_sql(&col_data.data)
    }

    /// Gets a returned record set by its zero-based index. Returns `None` if the
    /// index is out of range.
    pub fn to_query_result(&self, idx: usize) -> Option<&Vec<Row>> {
        self.query_results.get(idx)
    }
}

impl IntoIterator for CommandResult {
    type Item = Vec<Row>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.query_results.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tds::codec::ColumnData;

    impl ExecuteResult {
        fn from_counts(counts: Vec<u64>) -> Self {
            Self {
                rows_affected: counts,
            }
        }
    }

    #[test]
    fn execute_result_rows_affected_preserves_order_and_values() {
        let res = ExecuteResult::from_counts(vec![3, 0, 7]);
        assert_eq!(res.rows_affected(), &[3, 0, 7]);
    }

    #[test]
    fn execute_result_total_sums_every_count() {
        assert_eq!(ExecuteResult::from_counts(vec![3, 0, 7]).total(), 10);
    }

    #[test]
    fn execute_result_into_iter_yields_each_count() {
        let counts: Vec<u64> = ExecuteResult::from_counts(vec![5, 9]).into_iter().collect();
        assert_eq!(counts, vec![5, 9]);
    }

    fn return_value(name: &str, value: i32) -> CommandReturnValue {
        CommandReturnValue {
            name: name.to_string(),
            ord: 0,
            data: ColumnData::I32(Some(value)),
        }
    }

    fn command_result() -> CommandResult {
        CommandResult {
            rows_affected: vec![2, 4],
            return_code: 7,
            return_values: vec![return_value("@a", 1), return_value("@b", 42)],
            // Two (empty) record sets so `to_query_result` has Some values to return.
            query_results: vec![Vec::new(), Vec::new()],
        }
    }

    #[test]
    fn command_result_scalar_accessors() {
        let res = command_result();
        assert_eq!(res.rows_affected(), &[2, 4]);
        assert_eq!(res.return_code(), 7);
        assert_eq!(res.return_values_len(), 2);
    }

    #[test]
    fn command_result_to_query_result_indexes_record_sets() {
        let res = command_result();
        assert!(res.to_query_result(0).is_some());
        assert!(res.to_query_result(1).is_some());
        assert!(res.to_query_result(2).is_none());
    }

    #[test]
    fn command_result_try_return_value_reads_named_out_param() {
        let res = command_result();
        let got: Option<i32> = res.try_return_value("@b").unwrap();
        assert_eq!(got, Some(42));
        assert!(res.try_return_value::<i32>("@missing").is_err());
    }

    #[test]
    fn command_result_into_iter_yields_each_record_set() {
        assert_eq!(command_result().into_iter().count(), 2);
    }
}
