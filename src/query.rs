use std::borrow::Cow;

use futures_util::io::{AsyncRead, AsyncWrite};

use crate::{
    tds::{codec::RpcProcId, stream::TokenStream},
    Client, ColumnData, ExecuteResult, IntoSql, QueryStream,
};

/// A query object with bind parameters.
#[derive(Debug)]
pub struct Query<'a> {
    sql: Cow<'a, str>,
    params: Vec<ColumnData<'a>>,
}

impl<'a> Query<'a> {
    /// Construct a new query object with the given SQL. If the SQL is
    /// parameterized, the given number of parameters must be bound to the
    /// object before executing.
    ///
    /// The `sql` can define the parameter placement by annotating them with
    /// `@PN`, where N is the index of the parameter, starting from `1`.
    pub fn new(sql: impl Into<Cow<'a, str>>) -> Self {
        Self {
            sql: sql.into(),
            params: Vec::new(),
        }
    }

    /// Bind a new parameter to the query. Must be called exactly as many times
    /// as there are parameters in the given SQL. Otherwise the query will fail
    /// on execution.
    pub fn bind(&mut self, param: impl IntoSql<'a> + 'a) {
        self.params.push(param.into_sql());
    }

    /// Bind every item of an iterator, in order.
    ///
    /// Equivalent to calling [`bind`] once per item. Pairs with
    /// [`placeholders`] to build an `IN` list, where the number of
    /// parameters is only known at runtime.
    ///
    /// # Example
    ///
    /// ```
    /// # use tiberius::Query;
    /// let ids = vec![1i32, 2, 3];
    ///
    /// let sql = format!(
    ///     "SELECT name FROM users WHERE id IN ({})",
    ///     Query::placeholders(1, ids.len()),
    /// );
    ///
    /// let mut query = Query::new(sql);
    /// query.bind_iter(ids);
    ///
    /// assert_eq!(query.param_count(), 3);
    /// ```
    ///
    /// [`bind`]: #method.bind
    /// [`placeholders`]: #method.placeholders
    pub fn bind_iter(&mut self, params: impl IntoIterator<Item = impl IntoSql<'a> + 'a>) {
        for param in params {
            self.bind(param);
        }
    }

    /// How many parameters have been bound so far.
    ///
    /// Useful for checking against [`MAX_PARAMETERS`] before executing a
    /// statement whose parameter count is decided at runtime.
    ///
    /// [`MAX_PARAMETERS`]: #associatedconstant.MAX_PARAMETERS
    pub fn param_count(&self) -> usize {
        self.params.len()
    }

    /// The 2100-parameter server-side limit for one statement; split larger
    /// batches into chunks of at most `MAX_PARAMETERS / parameters_per_row` rows.
    ///
    /// # Example
    ///
    /// ```
    /// # use tiberius::Query;
    /// // A three-column INSERT: three parameters per row.
    /// let rows_per_statement = Query::MAX_PARAMETERS / 3;
    /// assert_eq!(rows_per_statement, 700);
    /// ```
    pub const MAX_PARAMETERS: usize = 2100;

    /// Builds `@P1, @P2, …` for `count` placeholders numbered from `first`
    /// (1-based).
    ///
    /// # Example
    ///
    /// ```
    /// # use tiberius::Query;
    /// assert_eq!(Query::placeholders(1, 3), "@P1, @P2, @P3");
    ///
    /// // Continuing after parameters that are already bound.
    /// assert_eq!(Query::placeholders(4, 2), "@P4, @P5");
    /// ```
    ///
    /// A count of zero yields an empty string. `IN ()` is a syntax error, so
    /// a caller with nothing to match on should skip the query rather than
    /// build one:
    ///
    /// ```
    /// # use tiberius::Query;
    /// let ids: Vec<i32> = Vec::new();
    /// assert!(Query::placeholders(1, ids.len()).is_empty());
    /// ```
    pub fn placeholders(first: usize, count: usize) -> String {
        use std::fmt::Write;

        let mut out = String::with_capacity(count * 6);

        for index in 0..count {
            if index > 0 {
                out.push_str(", ");
            }
            let _ = write!(out, "@P{}", first + index);
        }

        out
    }

    /// Executes SQL statements in the SQL Server, returning the number rows
    /// affected. Useful for `INSERT`, `UPDATE` and `DELETE` statements. See
    /// [`Client#execute`] for a simpler API if the parameters are statically
    /// known.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tiberius::{Config, Query};
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
    /// let mut query = Query::new("INSERT INTO ##Test (id) VALUES (@P1), (@P2), (@P3)");
    ///
    /// query.bind("foo");
    /// query.bind(2i32);
    /// query.bind(String::from("bar"));
    ///
    /// let results = query.execute(&mut client).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`ToSql`]: trait.ToSql.html
    /// [`FromSql`]: trait.FromSql.html
    /// [`Client#execute`]: struct.Client.html#method.execute
    pub async fn execute<S>(self, client: &mut Client<S>) -> crate::Result<ExecuteResult>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        client.connection.flush_stream().await?;

        let rpc_params = Client::<S>::rpc_params(self.sql);

        client
            .rpc_perform_query(RpcProcId::ExecuteSQL, rpc_params, self.params.into_iter())
            .await?;

        ExecuteResult::new(&mut client.connection).await
    }

    /// Executes SQL statements in the SQL Server, returning resulting rows.
    /// Useful for `SELECT` statements. See [`Client#query`] for a simpler API
    /// if the parameters are statically known.
    ///
    /// # Example
    ///
    /// ```
    /// # use tiberius::{Config, Query};
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
    /// let mut query = Query::new("SELECT @P1, @P2, @P3");
    ///
    /// query.bind(1i32);
    /// query.bind(2i32);
    /// query.bind(3i32);
    ///
    /// let stream = query.query(&mut client).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`QueryStream`]: struct.QueryStream.html
    /// [`ToSql`]: trait.ToSql.html
    /// [`FromSql`]: trait.FromSql.html
    /// [`Client#query`]: struct.Client.html#method.query
    pub async fn query<'b, S>(self, client: &'b mut Client<S>) -> crate::Result<QueryStream<'b>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        client.connection.flush_stream().await?;
        let rpc_params = Client::<S>::rpc_params(self.sql);

        client
            .rpc_perform_query(RpcProcId::ExecuteSQL, rpc_params, self.params.into_iter())
            .await?;

        let ts = TokenStream::new(&mut client.connection);
        let mut result = QueryStream::new(ts.try_unfold());
        result.forward_to_metadata().await?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_are_numbered_from_one() {
        assert_eq!(Query::placeholders(1, 1), "@P1");
        assert_eq!(Query::placeholders(1, 3), "@P1, @P2, @P3");
    }

    #[test]
    fn placeholders_can_continue_from_an_offset() {
        assert_eq!(Query::placeholders(4, 2), "@P4, @P5");
        assert_eq!(Query::placeholders(10, 1), "@P10");
    }

    #[test]
    fn no_placeholders_is_an_empty_string() {
        assert_eq!(Query::placeholders(1, 0), "");
        assert_eq!(Query::placeholders(7, 0), "");
    }

    #[test]
    fn placeholders_have_no_trailing_separator() {
        let list = Query::placeholders(1, 5);
        assert!(!list.ends_with(", "));
        assert_eq!(list.matches(',').count(), 4);
    }

    #[test]
    fn binding_an_iterator_counts_every_item() {
        let mut query = Query::new("SELECT 1");
        assert_eq!(query.param_count(), 0);

        query.bind_iter(vec![1i32, 2, 3]);
        assert_eq!(query.param_count(), 3);

        query.bind(4i32);
        assert_eq!(query.param_count(), 4);
    }

    #[test]
    fn binding_an_empty_iterator_binds_nothing() {
        let mut query = Query::new("SELECT 1");
        query.bind_iter(Vec::<i32>::new());
        assert_eq!(query.param_count(), 0);
    }

    #[test]
    fn a_generated_list_matches_the_number_of_bound_parameters() {
        let ids = vec![10i32, 20, 30, 40];
        let list = Query::placeholders(1, ids.len());

        let mut query = Query::new(format!("SELECT * FROM t WHERE id IN ({list})"));
        query.bind_iter(ids);

        assert_eq!(list.matches("@P").count(), query.param_count());
    }

    #[test]
    fn the_parameter_limit_is_the_documented_tds_maximum() {
        assert_eq!(Query::MAX_PARAMETERS, 2100);
        assert_eq!(Query::MAX_PARAMETERS / 3, 700);
    }
}
