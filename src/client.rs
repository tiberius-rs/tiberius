pub(crate) mod auth;
mod config;
mod connection;

mod tls;
#[cfg(any(
    feature = "rustls",
    feature = "native-tls",
    feature = "vendored-openssl"
))]
mod tls_stream;

pub use auth::*;
pub use config::*;
pub(crate) use connection::*;

use crate::bulk_options::{ColumnOrderHint, SortOrder, SqlBulkCopyOption, SqlBulkCopyOptions};
use crate::tds::codec::RpcValue;
use crate::tds::stream::ReceivedToken;
use crate::{
    result::ExecuteResult,
    tds::{
        codec::{self, IteratorJoin},
        stream::{QueryStream, TokenStream},
    },
    BulkLoadRequest, MetaDataColumn, SqlReadBytes, ToSql,
};
use codec::{
    BatchRequest, ColumnData, IsolationLevel, PacketHeader, RpcParam, RpcProcId, TokenRpcRequest,
    TransactionManagerRequest,
};
use enumflags2::BitFlags;
use futures_util::io::{AsyncRead, AsyncWrite};
use futures_util::stream::TryStreamExt;
use std::{borrow::Cow, fmt::Debug};

/// `Client` is the main entry point to the SQL Server, providing query
/// execution capabilities.
///
/// A `Client` is created using the [`Config`], defining the needed
/// connection options and capabilities.
///
/// # Example
///
/// ```no_run
/// # use tiberius::{Config, AuthMethod};
/// use tokio_util::compat::TokioAsyncWriteCompatExt;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut config = Config::new();
///
/// config.host("0.0.0.0");
/// config.port(1433);
/// config.authentication(AuthMethod::sql_server("SA", "<Mys3cureP4ssW0rD>"));
///
/// let tcp = tokio::net::TcpStream::connect(config.get_addr()).await?;
/// tcp.set_nodelay(true)?;
/// // Client is ready to use.
/// let client = tiberius::Client::connect(config, tcp.compat_write()).await?;
/// # Ok(())
/// # }
/// ```
///
/// # Cancellation safety
///
/// A single [`Client`] drives one connection and one request at a time. If a
/// `query`/`execute`/`simple_query` future — or the result stream it returns —
/// is dropped before the request has been sent in full and the response fully
/// consumed (for example under a `tokio::time::timeout` or a `select!` branch
/// that loses the race), the connection may be left mid-message and out of sync
/// with the server. A cancelled *write* is detected and any further use of that
/// connection fails cleanly; a result stream dropped mid-response cannot be
/// recovered. In both cases the safe course is to drop the `Client` and open a
/// new connection (a connection pool should discard the connection on error)
/// rather than reuse it.
///
/// [`Config`]: struct.Config.html
#[derive(Debug)]
pub struct Client<S: AsyncRead + AsyncWrite + Unpin + Send> {
    pub(crate) connection: Connection<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> Client<S> {
    /// Uses an instance of [`Config`] to specify the connection
    /// options required to connect to the database using an established
    /// tcp connection
    ///
    /// Note: `tcp_stream` is a connected stream, so some parts of the `Config`
    /// (such as multi-subnet failover, which selects between resolved
    /// addresses) must be handled while establishing that stream, outside of
    /// this constructor.
    ///
    /// [`Config`]: struct.Config.html
    pub async fn connect(config: Config, tcp_stream: S) -> crate::Result<Client<S>> {
        Ok(Client {
            connection: Connection::connect(config, tcp_stream).await?,
        })
    }

    /// Executes SQL statements in the SQL Server, returning the number rows
    /// affected. Useful for `INSERT`, `UPDATE` and `DELETE` statements. The
    /// `query` can define the parameter placement by annotating them with
    /// `@PN`, where N is the index of the parameter, starting from `1`. If
    /// executing multiple queries at a time, delimit them with `;` and refer to
    /// [`ExecuteResult`] how to get results for the separate queries.
    ///
    /// For mapping of Rust types when writing, see the documentation for
    /// [`ToSql`]. For reading data from the database, see the documentation for
    /// [`FromSql`].
    ///
    /// This API is not quite suitable for dynamic query parameters. In these
    /// cases using a [`Query`] object might be easier.
    ///
    /// # Errors
    ///
    /// Returns an error if the statement cannot be sent, if the server reports
    /// an error while executing it, or if the connection fails during the
    /// request.
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
    /// let results = client
    ///     .execute(
    ///         "INSERT INTO ##Test (id) VALUES (@P1), (@P2), (@P3)",
    ///         &[&1i32, &2i32, &3i32],
    ///     )
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`ExecuteResult`]: struct.ExecuteResult.html
    /// [`ToSql`]: trait.ToSql.html
    /// [`FromSql`]: trait.FromSql.html
    /// [`Query`]: struct.Query.html
    pub async fn execute<'a>(
        &mut self,
        query: impl Into<Cow<'a, str>>,
        params: &[&dyn ToSql],
    ) -> crate::Result<ExecuteResult> {
        self.connection.flush_stream().await?;
        let rpc_params = Self::rpc_params(query);

        let params = params.iter().map(|s| s.to_sql());
        self.rpc_perform_query(RpcProcId::ExecuteSQL, rpc_params, params)
            .await?;

        ExecuteResult::new(&mut self.connection).await
    }

    /// Executes SQL statements in the SQL Server, returning resulting rows.
    /// Useful for `SELECT` statements. The `query` can define the parameter
    /// placement by annotating them with `@PN`, where N is the index of the
    /// parameter, starting from `1`. If executing multiple queries at a time,
    /// delimit them with `;` and refer to [`QueryStream`] on proper stream
    /// handling.
    ///
    /// For mapping of Rust types when writing, see the documentation for
    /// [`ToSql`]. For reading data from the database, see the documentation for
    /// [`FromSql`].
    ///
    /// This API can be cumbersome for dynamic query parameters. In these cases,
    /// if fighting too much with the compiler, using a [`Query`] object might be
    /// easier.
    ///
    /// # Errors
    ///
    /// Returns an error if the statement cannot be sent, if the server reports
    /// an error while executing it, or if the connection fails during the
    /// request. Note that per-statement server errors may instead surface while
    /// consuming the returned [`QueryStream`].
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
    /// let stream = client
    ///     .query(
    ///         "SELECT @P1, @P2, @P3",
    ///         &[&1i32, &2i32, &3i32],
    ///     )
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`QueryStream`]: struct.QueryStream.html
    /// [`Query`]: struct.Query.html
    /// [`ToSql`]: trait.ToSql.html
    /// [`FromSql`]: trait.FromSql.html
    pub async fn query<'a, 'b>(
        &'a mut self,
        query: impl Into<Cow<'b, str>>,
        params: &'b [&'b dyn ToSql],
    ) -> crate::Result<QueryStream<'a>>
    where
        'a: 'b,
    {
        self.connection.flush_stream().await?;
        let rpc_params = Self::rpc_params(query);

        let params = params.iter().map(|p| p.to_sql());
        self.rpc_perform_query(RpcProcId::ExecuteSQL, rpc_params, params)
            .await?;

        let ts = TokenStream::new(&mut self.connection);
        let mut result = QueryStream::new(ts.try_unfold());
        result.forward_to_metadata().await?;

        Ok(result)
    }

    /// Execute multiple queries, delimited with `;` and return multiple result
    /// sets; one for each query.
    ///
    /// # Errors
    ///
    /// Returns an error if the batch cannot be sent, if the server reports an
    /// error while executing it, or if the connection fails during the request.
    /// Per-statement server errors may instead surface while consuming the
    /// returned [`QueryStream`].
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
    /// let row = client.simple_query("SELECT 1 AS col").await?.into_row().await?.unwrap();
    /// assert_eq!(Some(1i32), row.get("col"));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Warning
    ///
    /// Do not use this with any user specified input. Please resort to prepared
    /// statements using the [`query`] method.
    ///
    /// [`query`]: #method.query
    pub async fn simple_query<'a, 'b>(
        &'a mut self,
        query: impl Into<Cow<'b, str>>,
    ) -> crate::Result<QueryStream<'a>>
    where
        'a: 'b,
    {
        self.connection.flush_stream().await?;

        let req = BatchRequest::new(query, self.connection.context().transaction_descriptor());

        let id = self.connection.context_mut().next_packet_id();
        self.connection.send(PacketHeader::batch(id), req).await?;

        let ts = TokenStream::new(&mut self.connection);

        let mut result = QueryStream::new(ts.try_unfold());
        result.forward_to_metadata().await?;

        Ok(result)
    }

    /// Execute a `BULK INSERT` statement, efficiently storing a large number of
    /// rows to a specified table. Note: make sure the input row follows the same
    /// schema as the table, otherwise calling `send()` will return an error.
    ///
    /// This is equivalent to `bulk_insert_columns(table, &["*"])`, inserting into
    /// all of a table's columns.
    ///
    /// # Security
    ///
    /// `table` is interpolated **directly** into the SQL batch sent to the
    /// server. SQL Server does not allow table (or column) identifiers to be
    /// supplied as bound parameters, so this value cannot be parameterized — it
    /// becomes part of the SQL text verbatim. The caller MUST therefore pass a
    /// **trusted, hard-coded or otherwise validated** identifier and MUST NOT
    /// pass untrusted or user-supplied input, which would open a SQL injection
    /// vector. As cheap defense-in-depth this method rejects obviously-malformed
    /// identifiers (NUL/ASCII control characters or an unbalanced `]` bracket),
    /// but that guard is not a substitute for passing trusted input.
    ///
    /// # Errors
    ///
    /// Returns an error if `table` is a malformed identifier, if the column
    /// metadata query fails, or if the server rejects the `INSERT BULK`
    /// statement. Row-level failures surface later from [`send`] and
    /// [`finalize`] on the returned request.
    ///
    /// [`send`]: BulkLoadRequest::send
    /// [`finalize`]: BulkLoadRequest::finalize
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tiberius::{Config, IntoRow};
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
    /// let create_table = r#"
    ///     CREATE TABLE ##bulk_test (
    ///         id INT IDENTITY PRIMARY KEY,
    ///         val INT NOT NULL
    ///     )
    /// "#;
    ///
    /// client.simple_query(create_table).await?;
    ///
    /// // Start the bulk insert with the client.
    /// let mut req = client.bulk_insert("##bulk_test").await?;
    ///
    /// for i in [0i32, 1i32, 2i32] {
    ///     let row = (i).into_row();
    ///
    ///     // The request will handle flushing to the wire in an optimal way,
    ///     // balancing between memory usage and IO performance.
    ///     req.send(row).await?;
    /// }
    ///
    /// // The request must be finalized.
    /// let res = req.finalize().await?;
    /// assert_eq!(3, res.total());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn bulk_insert<'a>(
        &'a mut self,
        table: &'a str,
    ) -> crate::Result<BulkLoadRequest<'a, S>> {
        self.bulk_insert_columns(table, &["*"]).await
    }

    /// Execute a `BULK INSERT` statement, efficiently storing a large number of
    /// rows to a specified table. Note: make sure the input row follows the same
    /// schema as the column list, otherwise calling `send()` will return an error.
    ///
    /// # Security
    ///
    /// Both `table` and the entries of `columns` are interpolated **directly**
    /// into the SQL batches sent to the server (the `SELECT` used to fetch
    /// column metadata and the `INSERT BULK` statement). SQL Server does not
    /// allow identifiers to be supplied as bound parameters, so these values
    /// cannot be parameterized — they become part of the SQL text verbatim. The
    /// caller MUST therefore pass **trusted, hard-coded or otherwise validated**
    /// identifiers and MUST NOT pass untrusted or user-supplied input, which
    /// would open a SQL injection vector. As cheap defense-in-depth this method
    /// rejects an obviously-malformed `table` (NUL/ASCII control characters or an
    /// unbalanced `]` bracket), but that guard is not a substitute for passing
    /// trusted input.
    ///
    /// # Errors
    ///
    /// Returns an error if `table` is a malformed identifier, if the column
    /// metadata query fails, or if the server rejects the `INSERT BULK`
    /// statement. Row-level failures surface later from [`send`] and
    /// [`finalize`] on the returned request.
    ///
    /// [`send`]: BulkLoadRequest::send
    /// [`finalize`]: BulkLoadRequest::finalize
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tiberius::{Config, IntoRow};
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
    /// let create_table = r#"
    ///     CREATE TABLE ##bulk_test_columns (
    ///         id INT IDENTITY PRIMARY KEY,
    ///         foo INT NOT NULL,
    ///         bar FLOAT NOT NULL
    ///     )
    /// "#;
    ///
    /// client.simple_query(create_table).await?;
    ///
    /// // Start the bulk insert with the client.
    /// let mut req = client.bulk_insert_columns("##bulk_test_columns", &["foo", "bar"]).await?;
    ///
    /// for (i, j) in [(0i32, 0f64), (1i32, 1f64), (2i32, 2f64)] {
    ///     let row = (i, j).into_row();
    ///
    ///     // The request will handle flushing to the wire in an optimal way,
    ///     // balancing between memory usage and IO performance.
    ///     req.send(row).await?;
    /// }
    ///
    /// // The request must be finalized.
    /// let res = req.finalize().await?;
    /// assert_eq!(3, res.total());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn bulk_insert_columns<'a>(
        &'a mut self,
        table: &'a str,
        columns: &'a [&'a str],
    ) -> crate::Result<BulkLoadRequest<'a, S>> {
        self.bulk_insert_with_options(table, columns, SqlBulkCopyOptions::empty(), &[])
            .await
    }

    /// Execute a `BULK INSERT` statement like [`bulk_insert_columns`], with
    /// additional control over the emitted `WITH (...)` clause.
    ///
    /// `options` is a set of [`SqlBulkCopyOption`] flags (combine them with `|`,
    /// or pass [`SqlBulkCopyOptions::empty`] for none), and `order_hints`
    /// declares the sort order the incoming rows are already in via an
    /// `ORDER (...)` clause. Pass `&["*"]` as `columns` to target every column,
    /// exactly like [`bulk_insert`] does internally.
    ///
    /// When `options` is empty and `order_hints` is empty this emits the exact
    /// same statement as [`bulk_insert_columns`] (no `WITH` clause).
    ///
    /// # Security
    ///
    /// `table`, every entry of `columns`, and every order-hint column name are
    /// interpolated **directly** into the SQL batches sent to the server (T-SQL
    /// does not allow identifiers to be parameterized). The caller MUST pass
    /// **trusted, hard-coded or otherwise validated** identifiers and MUST NOT
    /// pass untrusted or user-supplied input. As cheap defense-in-depth this
    /// method rejects obviously-malformed identifiers — NUL/ASCII control
    /// characters, an unbalanced `]` bracket, a top-level space, statement-
    /// breaking punctuation (`;`, quotes, `-`, etc.) and tokens spliced onto a
    /// closing `]`/`)` — for the table, columns *and* order-hint columns, but
    /// that guard is not a substitute for passing trusted input.
    ///
    /// # Errors
    ///
    /// Returns an error if `table`, a column, or an order-hint column is a
    /// malformed identifier, if the column metadata query fails, or if the
    /// server rejects the `INSERT BULK` statement. Row-level failures surface
    /// later from [`send`] and [`finalize`] on the returned request.
    ///
    /// [`bulk_insert`]: #method.bulk_insert
    /// [`bulk_insert_columns`]: #method.bulk_insert_columns
    /// [`send`]: BulkLoadRequest::send
    /// [`finalize`]: BulkLoadRequest::finalize
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tiberius::{Config, IntoRow, SqlBulkCopyOption, SortOrder};
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
    /// let mut req = client
    ///     .bulk_insert_with_options(
    ///         "##bulk_test",
    ///         &["id", "val"],
    ///         SqlBulkCopyOption::KeepIdentity | SqlBulkCopyOption::TableLock,
    ///         &[("id", SortOrder::Ascending)],
    ///     )
    ///     .await?;
    ///
    /// for i in [0i32, 1i32, 2i32] {
    ///     req.send((i, i).into_row()).await?;
    /// }
    ///
    /// let res = req.finalize().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn bulk_insert_with_options<'a>(
        &'a mut self,
        table: &'a str,
        columns: &'a [&'a str],
        options: SqlBulkCopyOptions,
        order_hints: &'a [ColumnOrderHint<'a>],
    ) -> crate::Result<BulkLoadRequest<'a, S>> {
        // `table` is interpolated directly into the SQL batch (identifiers cannot
        // be parameterized in T-SQL). Reject obviously-malformed/dangerous input
        // as cheap defense-in-depth; see the `# Security` note above.
        validate_bulk_table_identifier(table)?;

        // Each `columns` entry is likewise interpolated directly into the SQL
        // (both the metadata `SELECT` and the `INSERT BULK` column list), so it
        // gets the same cheap defense-in-depth guard as `table`.
        for column in columns {
            validate_bulk_column_identifier(column)?;
        }

        // Order-hint column names are interpolated into the `ORDER (...)` clause,
        // so they get the exact same guard (and, below, the same bracket
        // escaping) as the regular column list.
        for &(column, _) in order_hints {
            validate_bulk_column_identifier(column)?;
        }

        // Retrieve column metadata from the server, keeping only the updateable
        // columns as bulk targets (read-only/computed columns are skipped).
        //
        // Identity columns are normally read-only (so filtered out, letting the
        // server assign values), but `KEEP_IDENTITY` is implemented — exactly as
        // ADO.NET's `SqlBulkCopy` does — by *including* the identity column in
        // the bulk column list so the caller supplies explicit values; there is
        // no `KEEP_IDENTITY` keyword in the `INSERT BULK` `WITH (...)` grammar.
        // So when the flag is set, identity columns are additionally retained.
        let keep_identity = options.contains(SqlBulkCopyOption::KeepIdentity);
        let mut columns: Vec<_> = self
            .column_metadata(table, columns)
            .await?
            .into_iter()
            .filter(|column| bulk_column_is_target(&column.base, keep_identity))
            .collect();

        // `text`/`ntext`/`image` columns must carry the destination TableName in
        // the COLMETADATA we emit for the bulk load (MS-TDS §2.2.7.4). Record the
        // target table on every column; the encoder only emits it for those
        // types, so this is a no-op on the wire for all other columns.
        for column in columns.iter_mut() {
            column.base.table_name = Some(table.to_string());
        }

        // now start bulk upload
        self.connection.flush_stream().await?;
        let col_data = columns.iter().map(|c| format!("{}", c)).join(", ");
        let query = build_insert_bulk_sql(table, &col_data, options, order_hints);

        let req = BatchRequest::new(query, self.connection.context().transaction_descriptor());
        let id = self.connection.context_mut().next_packet_id();

        self.connection.send(PacketHeader::batch(id), req).await?;

        let ts = TokenStream::new(&mut self.connection);
        ts.flush_done().await?;

        BulkLoadRequest::new(&mut self.connection, columns)
    }

    /// Retrieve the column metadata for a set of columns of a table, including
    /// the column names, types (with their size, precision and scale) and flags
    /// such as nullability and whether a column is an identity column.
    ///
    /// Pass `&["*"]` as `columns` to return the metadata for every column of the
    /// table.
    ///
    /// # Security
    ///
    /// Both `table` and the entries of `columns` are interpolated **directly**
    /// into the SQL batch sent to the server (`SELECT TOP 0 {columns} FROM
    /// {table}`). SQL Server does not allow identifiers to be supplied as bound
    /// parameters, so these values cannot be parameterized — they become part of
    /// the SQL text verbatim. The caller MUST therefore pass **trusted,
    /// hard-coded or otherwise validated** identifiers and MUST NOT pass
    /// untrusted or user-supplied input, which would open a SQL injection
    /// vector. As cheap defense-in-depth this method rejects obviously-malformed
    /// identifiers (NUL/ASCII control characters or an unbalanced `]` bracket),
    /// but that guard is not a substitute for passing trusted input.
    ///
    /// # Errors
    ///
    /// Returns an error if `table` is a malformed identifier, if the metadata
    /// `SELECT` fails, or if the server reports an error while executing it.
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
    /// let meta = client.column_metadata("some_table", &["*"]).await?;
    /// assert!(meta[0].base().is_identity());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn column_metadata(
        &mut self,
        table: &str,
        columns: &[&str],
    ) -> crate::Result<Vec<MetaDataColumn<'static>>> {
        // `table` and each `column` are interpolated directly into the SQL
        // batch below (identifiers cannot be parameterized in T-SQL). Reject
        // obviously-malformed/dangerous input as cheap defense-in-depth; see the
        // `# Security` note above.
        validate_bulk_table_identifier(table)?;
        for column in columns {
            validate_bulk_column_identifier(column)?;
        }

        self.connection.flush_stream().await?;

        // Ask the server for the column layout without returning any rows.
        let columns = columns.join(", ");
        let query = format!("SELECT TOP 0 {columns} FROM {table}");

        let req = BatchRequest::new(query, self.connection.context().transaction_descriptor());
        let id = self.connection.context_mut().next_packet_id();
        self.connection.send(PacketHeader::batch(id), req).await?;

        let token_stream = TokenStream::new(&mut self.connection).try_unfold();

        let columns = token_stream
            .try_fold(None, |mut columns, token| async move {
                if let ReceivedToken::NewResultset(metadata) = token {
                    columns = Some(metadata.columns.clone());
                };

                Ok(columns)
            })
            .await?;

        let columns = columns.ok_or_else(|| {
            crate::Error::Protocol("expecting column metadata from query but not found".into())
        })?;

        // Own the column names so the returned metadata is not tied to the
        // lifetime of the token stream.
        Ok(columns
            .into_iter()
            .map(|c| MetaDataColumn {
                base: c.base,
                col_name: std::borrow::Cow::Owned(c.col_name.into_owned()),
            })
            .collect())
    }

    /// Sends a TDS Attention signal to the server (packet type `0x06`,
    /// MS-TDS section 2.2.1.6) to cancel the request that is currently in
    /// flight on this connection, and drains the acknowledging token stream so
    /// the connection can be reused for further queries.
    ///
    /// The server responds to the Attention signal by aborting the running
    /// batch or RPC and returning a `DONE` token with the `DONE_ATTN` status
    /// bit set. This method waits for that acknowledgement before returning,
    /// discarding any remaining rows or tokens from the cancelled request.
    ///
    /// # Query cancellation and futures
    ///
    /// Dropping a [`query`], [`execute`] or [`simple_query`] future (for
    /// example when a `tokio::time::timeout` elapses or a `select!` branch is
    /// cancelled) stops the client from polling the stream, but it does *not*
    /// tell the server to stop working on the request. To actually cancel the
    /// in-flight work on the server, keep the [`Client`] and call
    /// `cancel_query` on it. Because `cancel_query` borrows the client
    /// mutably, it can only be issued once the borrowing result stream has
    /// been dropped — typically from a separate task holding the client, or
    /// after a cancelled/timed-out future has released its borrow.
    ///
    /// [`query`]: #method.query
    /// [`execute`]: #method.execute
    /// [`simple_query`]: #method.simple_query
    pub async fn cancel_query(&mut self) -> crate::Result<()> {
        self.connection.cancel_request().await?;
        Ok(())
    }

    /// Closes this database connection explicitly.
    pub async fn close(self) -> crate::Result<()> {
        self.connection.close().await
    }

    /// Begins a new transaction using a Transaction Manager request
    /// (`TM_BEGIN_XACT`, MS-TDS 2.2.6.8) instead of a `BEGIN TRAN` T-SQL
    /// batch.
    ///
    /// On success the server replies with a `BeginTransaction` environment
    /// change token whose descriptor is stored in the connection context and
    /// automatically attached to subsequent requests, scoping them to the
    /// transaction. Commit the work with [`commit_transaction`] or discard it
    /// with [`rollback_transaction`].
    ///
    /// The transaction uses the server's default isolation level. Use
    /// [`begin_transaction_with_isolation`] to request a specific one.
    ///
    /// [`commit_transaction`]: #method.commit_transaction
    /// [`rollback_transaction`]: #method.rollback_transaction
    /// [`begin_transaction_with_isolation`]: #method.begin_transaction_with_isolation
    pub async fn begin_transaction(&mut self) -> crate::Result<()> {
        self.begin_transaction_with_isolation(IsolationLevel::Unspecified)
            .await
    }

    /// Begins a new transaction with an explicit isolation level using a
    /// Transaction Manager request (`TM_BEGIN_XACT`, MS-TDS 2.2.6.8).
    ///
    /// See [`begin_transaction`] for details on transaction scoping.
    ///
    /// [`begin_transaction`]: #method.begin_transaction
    pub async fn begin_transaction_with_isolation(
        &mut self,
        isolation_level: IsolationLevel,
    ) -> crate::Result<()> {
        let req = TransactionManagerRequest::begin(
            self.connection.context().transaction_descriptor(),
            isolation_level,
            "",
        );

        self.send_transaction_manager_request(req).await
    }

    /// Commits the active transaction using a Transaction Manager request
    /// (`TM_COMMIT_XACT`, MS-TDS 2.2.6.8).
    ///
    /// After a successful commit the connection is no longer scoped to a
    /// transaction.
    pub async fn commit_transaction(&mut self) -> crate::Result<()> {
        let req = TransactionManagerRequest::commit(
            self.connection.context().transaction_descriptor(),
            "",
        );

        self.send_transaction_manager_request(req).await
    }

    /// Rolls back the active transaction using a Transaction Manager request
    /// (`TM_ROLLBACK_XACT`, MS-TDS 2.2.6.8).
    ///
    /// After a successful rollback the connection is no longer scoped to a
    /// transaction.
    pub async fn rollback_transaction(&mut self) -> crate::Result<()> {
        let req = TransactionManagerRequest::rollback(
            self.connection.context().transaction_descriptor(),
            "",
        );

        self.send_transaction_manager_request(req).await
    }

    /// Creates a named savepoint in the active transaction using a Transaction
    /// Manager request (`TM_SAVE_XACT`, MS-TDS 2.2.6.8).
    ///
    /// The savepoint can later be targeted by a T-SQL `ROLLBACK TRANSACTION
    /// <name>` to undo work performed after it while keeping the surrounding
    /// transaction open.
    pub async fn save_transaction<'a>(
        &mut self,
        name: impl Into<Cow<'a, str>>,
    ) -> crate::Result<()> {
        let req = TransactionManagerRequest::save(
            self.connection.context().transaction_descriptor(),
            name,
        );

        self.send_transaction_manager_request(req).await
    }

    async fn send_transaction_manager_request(
        &mut self,
        req: TransactionManagerRequest<'_>,
    ) -> crate::Result<()> {
        self.connection.flush_stream().await?;

        let id = self.connection.context_mut().next_packet_id();
        self.connection
            .send(PacketHeader::transaction_manager(id), req)
            .await?;

        // The server responds with a DONE token (plus an ENVCHANGE token that
        // the token stream applies to the connection context, updating the
        // active transaction descriptor).
        TokenStream::new(&mut self.connection).flush_done().await?;

        Ok(())
    }

    pub(crate) fn rpc_params<'a>(query: impl Into<Cow<'a, str>>) -> Vec<RpcParam<'a>> {
        vec![
            RpcParam {
                name: Cow::Borrowed("stmt"),
                flags: BitFlags::empty(),
                value: RpcValue::Scalar(ColumnData::String(Some(query.into()))),
            },
            RpcParam {
                name: Cow::Borrowed("params"),
                flags: BitFlags::empty(),
                value: RpcValue::Scalar(ColumnData::I32(Some(0))),
            },
        ]
    }

    pub(crate) async fn rpc_perform_query<'a, 'b>(
        &'a mut self,
        proc_id: RpcProcId,
        mut rpc_params: Vec<RpcParam<'b>>,
        params: impl Iterator<Item = ColumnData<'b>>,
    ) -> crate::Result<()>
    where
        'a: 'b,
    {
        let mut param_str = String::new();

        for (i, param) in params.enumerate() {
            if i > 0 {
                param_str.push(',')
            }
            param_str.push_str(&format!("@P{} ", i + 1));
            param_str.push_str(&param.type_name());

            rpc_params.push(RpcParam {
                name: Cow::Owned(format!("@P{}", i + 1)),
                flags: BitFlags::empty(),
                value: RpcValue::Scalar(param),
            });
        }

        if let Some(params) = rpc_params.iter_mut().find(|x| x.name == "params") {
            params.value = RpcValue::Scalar(ColumnData::String(Some(param_str.into())));
        }

        let req = TokenRpcRequest::new(
            proc_id,
            rpc_params,
            self.connection.context().transaction_descriptor(),
        );

        let id = self.connection.context_mut().next_packet_id();
        self.connection.send(PacketHeader::rpc(id), req).await?;

        Ok(())
    }

    /// Sends a named-procedure RPC request with the given parameters. The caller
    /// is responsible for flushing the connection beforehand and for consuming
    /// the resulting token stream.
    pub(crate) async fn rpc_run_command<'a, 'b>(
        &'a mut self,
        command_name: Cow<'b, str>,
        rpc_params: Vec<RpcParam<'b>>,
    ) -> crate::Result<()>
    where
        'a: 'b,
    {
        let req = TokenRpcRequest::new(
            command_name,
            rpc_params,
            self.connection.context().transaction_descriptor(),
        );

        let id = self.connection.context_mut().next_packet_id();
        self.connection.send(PacketHeader::rpc(id), req).await?;

        Ok(())
    }

    /// Runs a batch query solely to retrieve its column metadata. Used to
    /// resolve the column layout of a table-valued parameter type.
    pub(crate) async fn query_run_for_metadata<'b>(
        &mut self,
        query: String,
    ) -> crate::Result<Option<Vec<MetaDataColumn<'b>>>> {
        self.connection.flush_stream().await?;

        let req = BatchRequest::new(query, self.connection.context().transaction_descriptor());

        let id = self.connection.context_mut().next_packet_id();
        self.connection.send(PacketHeader::batch(id), req).await?;

        let token_stream = TokenStream::new(&mut self.connection).try_unfold();

        let columns = token_stream
            .try_fold(None, |mut columns, token| async move {
                if let ReceivedToken::NewResultset(metadata) = token {
                    columns = Some(metadata.columns.clone());
                };

                Ok(columns)
            })
            .await?;

        Ok(columns)
    }
}

/// Build the `INSERT BULK <table> (<cols>) [WITH (...)]` statement text.
///
/// `col_data` is the already-formatted column list (each column bracket-quoted
/// with its type, joined by `, `). Active [`SqlBulkCopyOptions`] flags and any
/// `order_hints` are collected into a `WITH (...)` clause; when both are empty
/// no `WITH` clause is emitted, so this reproduces the plain
/// `INSERT BULK <table> (<cols>)` used by `bulk_insert_columns`.
///
/// Order-hint column names are interpolated verbatim as already-valid SQL
/// identifiers — exactly like `table` and the `columns` entries elsewhere in
/// this module — so a caller may pass a plain (`id`), bracket-quoted (`[id]`,
/// `[my]]col]`) or multi-part name and get that same text back. Callers are
/// expected to have run every identifier through [`validate_bulk_column_identifier`]
/// first; do NOT re-bracket here, or an already-quoted name like `[id]` would be
/// double-escaped into the wrong identifier `[[id]]]`.
///
/// Note there is deliberately no `KEEP_IDENTITY` keyword: the `INSERT BULK`
/// `WITH (...)` grammar has no such option (unlike the textual `BULK INSERT`
/// statement). [`SqlBulkCopyOption::KeepIdentity`] is honoured by the caller
/// keeping the identity column in `col_data` instead.
fn build_insert_bulk_sql(
    table: &str,
    col_data: &str,
    options: SqlBulkCopyOptions,
    order_hints: &[ColumnOrderHint<'_>],
) -> String {
    let mut clauses: Vec<String> = Vec::new();

    // NB: `KeepIdentity` intentionally emits no keyword here — it is a
    // column-inclusion concern handled in `bulk_insert_with_options`.
    if options.contains(SqlBulkCopyOption::CheckConstraints) {
        clauses.push("CHECK_CONSTRAINTS".to_owned());
    }
    if options.contains(SqlBulkCopyOption::TableLock) {
        clauses.push("TABLOCK".to_owned());
    }
    if options.contains(SqlBulkCopyOption::KeepNulls) {
        clauses.push("KEEP_NULLS".to_owned());
    }
    if options.contains(SqlBulkCopyOption::FireTriggers) {
        clauses.push("FIRE_TRIGGERS".to_owned());
    }

    if !order_hints.is_empty() {
        let hints = order_hints
            .iter()
            .map(|(col, order)| {
                // Interpolate the (already-validated) identifier verbatim, like
                // `table`/`columns`. Re-bracketing here would double-escape an
                // already-quoted name (`[id]` -> `[[id]]]`).
                format!(
                    "{col} {}",
                    match order {
                        SortOrder::Ascending => "ASC",
                        SortOrder::Descending => "DESC",
                    }
                )
            })
            .join(", ");

        clauses.push(format!("ORDER({hints})"));
    }

    let mut query = format!("INSERT BULK {table} ({col_data})");

    if !clauses.is_empty() {
        query.push_str(" WITH (");
        query.push_str(&clauses.join(", "));
        query.push(')');
    }

    query
}

/// Decide whether a server-reported column is a bulk-insert target.
///
/// Read-only/computed columns are skipped so the server assigns their values.
/// Identity columns are read-only by default (filtered out, letting the server
/// assign them), but when [`SqlBulkCopyOption::KeepIdentity`] is set they are
/// additionally retained so the caller can supply explicit values — matching
/// ADO.NET's `SqlBulkCopy` (there is no `KEEP_IDENTITY` keyword in the
/// `INSERT BULK` `WITH (...)` grammar). Factored out of
/// [`Client::bulk_insert_with_options`] so this selection logic is unit-testable
/// without a live server.
fn bulk_column_is_target(
    base: &crate::tds::codec::BaseMetaDataColumn,
    keep_identity: bool,
) -> bool {
    base.is_updateable() || (keep_identity && base.is_identity())
}

/// Reject an obviously-malformed or dangerous bulk-insert table identifier.
///
/// The `table` argument of [`Client::bulk_insert`] / [`Client::bulk_insert_columns`]
/// is interpolated directly into the SQL batch because T-SQL does not allow
/// identifiers to be parameterized. This guard is cheap defense-in-depth — it
/// does NOT make untrusted input safe. It only rejects input that cannot be a
/// legitimate identifier (see [`validate_sql_identifier`] for the exact rules).
///
/// It deliberately does NOT try to quote or rewrite the identifier, so
/// multi-part names (`schema.table`), already-bracketed names (`[my table]`) and
/// temp tables (`##bulk_test`) keep working unchanged.
fn validate_bulk_table_identifier(table: &str) -> crate::Result<()> {
    validate_sql_identifier("bulk insert table", table)
}

/// Reject an obviously-malformed or dangerous bulk-insert `column` identifier.
///
/// Column names are interpolated into the metadata `SELECT` and `INSERT BULK`
/// column list exactly like `table`, so they get the same cheap
/// defense-in-depth check. See [`validate_bulk_table_identifier`].
fn validate_bulk_column_identifier(column: &str) -> crate::Result<()> {
    validate_sql_identifier("bulk insert column", column)
}

/// Reject an obviously-malformed or dangerous SQL identifier that will be
/// interpolated directly into a SQL batch because T-SQL does not allow
/// identifiers or type names to be parameterized. `what` names the kind of
/// identifier for the error message.
///
/// This is cheap defense-in-depth — it does NOT make untrusted input safe. It
/// rejects input that cannot be a legitimate identifier:
///
/// - a NUL byte or any ASCII control character;
/// - **outside** a `[...]` bracket-quoted segment, any character that is not
///   identifier-safe. Only alphanumerics and the punctuation needed for real
///   identifiers/type names are allowed — `_`, `.` (multi-part names like
///   `dbo.MyType`), `@`/`#` (variable/temp-style names), `*` (a bulk column
///   list may be `*`), and `(`, `)`, `,` (parameterized types such as
///   `decimal(10,2)` / `varchar(max)`). Parens must be balanced — an unbalanced
///   `)` *or* an unclosed `(` is rejected — and both a space and a comma are allowed only *inside*
///   those parens (e.g. `decimal(18, 4)`); a top-level space or comma is
///   rejected because it would let one identifier split into several SQL tokens
///   (a top-level comma would splice a verbatim order hint `a,b` into two
///   columns). This rejects statement-breaking characters such as `;`, quotes
///   and `-`, so a value like `1; DROP TABLE Users--` cannot slip through; and
/// - **inside** a `[...]` bracket-quoted segment anything is allowed except an
///   unescaped `]` (per the T-SQL bracket-escaping rule a literal `]` must be
///   doubled as `]]`). The segment must be terminated — an unclosed `[` running
///   to the end of the string is rejected. A `]` seen outside any bracket is
///   unbalanced and rejected. A closing `]`, and a top-level closing `)`, are themselves SQL
///   token boundaries, so a segment may only be followed by `.` (the next part
///   of a multi-part name) or the end of the string — this stops delimiter-
///   adjacent splicing such as `[t]UNION(...)` or `foo(1)UNION(...)` that needs
///   no space.
///
/// It deliberately does NOT try to quote or rewrite the identifier, so
/// multi-part names (`schema.table`), already-bracketed names (`[my table]`,
/// `[dbo].[my table]`, `[weird]]name]`) and temp tables (`##bulk_test`) keep
/// working unchanged. This is shared by the bulk-insert guards here and by
/// `validate_db_type_identifier` in `src/command.rs`.
pub(crate) fn validate_sql_identifier(what: &str, ident: &str) -> crate::Result<()> {
    if ident.chars().any(|c| c.is_ascii_control()) {
        return Err(crate::Error::BulkInput(
            format!("{what} identifier must not contain NUL or control characters").into(),
        ));
    }

    // Apply the T-SQL bracket rule: inside a `[...]` quoted identifier a literal
    // `]` must be doubled (`]]`); a single `]` closes the bracket. A `]` seen
    // outside of any bracket is unbalanced and rejected. Tracking bracket state
    // keeps legitimate names like `[dbo].[my table]` and `[weird]]name]`
    // working while catching stray closing brackets such as `Foo]`.
    let mut chars = ident.chars().peekable();
    let mut in_bracket = false;
    let mut paren_depth: u32 = 0;
    while let Some(c) = chars.next() {
        if in_bracket {
            if c == ']' {
                if chars.peek() == Some(&']') {
                    chars.next(); // consume the doubled `]]` escape
                } else {
                    in_bracket = false;
                    // A quoted-identifier segment may only be followed by `.`
                    // (introducing the next part of a multi-part name) or the
                    // end of the string. Anything else — e.g. `[t]UNION ...` —
                    // splices a fresh SQL token directly onto the closing `]`
                    // (which is itself a token boundary, needing no space), so
                    // reject it.
                    match chars.peek() {
                        None | Some('.') => {}
                        Some(_) => {
                            return Err(crate::Error::BulkInput(
                                format!("{what} identifier has trailing characters after a bracket-quoted segment").into(),
                            ));
                        }
                    }
                }
            }
            continue;
        }

        match c {
            '[' => in_bracket = true,
            ']' => {
                return Err(crate::Error::BulkInput(
                    format!("{what} identifier contains an unbalanced `]` bracket").into(),
                ));
            }
            '(' => paren_depth += 1,
            ')' => {
                // A `)` with no matching `(` is unbalanced. Left unchecked
                // (`saturating_sub`) it would sail through and, interpolated
                // verbatim, could close a caller-supplied enclosing paren early
                // — e.g. an order hint `col)` desyncing `ORDER(col) ...)`. Reject
                // it exactly like an unbalanced `]`.
                if paren_depth == 0 {
                    return Err(crate::Error::BulkInput(
                        format!("{what} identifier contains an unbalanced `)`").into(),
                    ));
                }
                paren_depth -= 1;
                // A parameterized type ends at its closing paren; nothing is a
                // legitimate continuation after a top-level `)`. Rejecting it
                // stops `)`-delimited token splicing such as `foo(1)UNION(...)`
                // (the `)` is a token boundary, so no space is required).
                if paren_depth == 0 && chars.peek().is_some() {
                    return Err(crate::Error::BulkInput(
                        format!("{what} identifier has trailing characters after a closing `)`")
                            .into(),
                    ));
                }
            }
            // A space is only legitimate inside a parameterized type's parens
            // (e.g. `decimal(18, 4)`) or inside a bracket-quoted name (handled
            // above). A *top-level* space would let a single identifier split
            // into several SQL tokens (`t UNION SELECT ...`, `t WHERE ...`)
            // without using any otherwise-blocked character, so reject it.
            ' ' if paren_depth == 0 => {
                return Err(crate::Error::BulkInput(
                    format!("{what} identifier contains a disallowed character").into(),
                ));
            }
            // A comma is only legitimate inside a parameterized type's parens
            // (`decimal(10,2)`). A *top-level* comma would splice a single
            // identifier into two — e.g. a verbatim order hint `a,b` becoming
            // two order columns `a` and `b` — so reject it like a top-level
            // space.
            ',' if paren_depth == 0 => {
                return Err(crate::Error::BulkInput(
                    format!("{what} identifier contains a disallowed character").into(),
                ));
            }
            // Outside a bracket-quoted segment only identifier-safe characters
            // are permitted (see the doc comment). Everything else — `;`,
            // quotes, `-`, etc. — is rejected.
            c if c.is_alphanumeric() => {}
            '_' | '.' | '@' | '#' | ',' | ' ' | '*' => {}
            _ => {
                return Err(crate::Error::BulkInput(
                    format!("{what} identifier contains a disallowed character").into(),
                ));
            }
        }
    }

    // Reject unbalanced *openers* left dangling at end of input, mirroring the
    // rejection of unbalanced closers above. An unterminated `[` would quote and
    // swallow whatever follows when interpolated (e.g. an order hint `[abc`
    // becoming `ORDER([abc ASC))`); an unclosed `(` leaves an enclosing paren
    // open. A legitimate identifier/type name never ends mid-bracket or with an
    // open paren.
    if in_bracket {
        return Err(crate::Error::BulkInput(
            format!("{what} identifier has an unterminated `[` bracket-quoted segment").into(),
        ));
    }
    if paren_depth != 0 {
        return Err(crate::Error::BulkInput(
            format!("{what} identifier contains an unbalanced `(`").into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        build_insert_bulk_sql, bulk_column_is_target, validate_bulk_column_identifier,
        validate_bulk_table_identifier,
    };
    use crate::tds::codec::{BaseMetaDataColumn, ColumnFlag, TypeInfo, VarLenContext, VarLenType};
    use crate::{SortOrder, SqlBulkCopyOption, SqlBulkCopyOptions};
    use enumflags2::BitFlags;

    // Build a `BaseMetaDataColumn` carrying exactly `flags`, so the bulk-target
    // selection predicate can be exercised without a live server. The column
    // type is irrelevant to the predicate; a small fixed-len type stands in.
    fn base_with_flags(flags: BitFlags<ColumnFlag>) -> BaseMetaDataColumn {
        BaseMetaDataColumn {
            flags,
            ty: TypeInfo::VarLenSized(VarLenContext::new(VarLenType::Intn, 4, None)),
            table_name: None,
        }
    }

    #[test]
    fn bulk_column_is_target_selects_writeable_and_keep_identity() {
        let updateable: BitFlags<ColumnFlag> = ColumnFlag::Updateable.into();
        let unknown: BitFlags<ColumnFlag> = ColumnFlag::UpdateableUnknown.into();
        let read_only = BitFlags::<ColumnFlag>::empty();
        let identity_ro: BitFlags<ColumnFlag> = ColumnFlag::Identity.into();
        // An identity column SQL Server also reports as updateable-unknown.
        let identity_unknown = ColumnFlag::Identity | ColumnFlag::UpdateableUnknown;

        // Read/write and updateable-unknown columns are always targets,
        // regardless of the KeepIdentity flag.
        for keep in [false, true] {
            assert!(bulk_column_is_target(&base_with_flags(updateable), keep));
            assert!(bulk_column_is_target(&base_with_flags(unknown), keep));
            // A plain read-only (non-identity) column is never a target.
            assert!(!bulk_column_is_target(&base_with_flags(read_only), keep));
        }

        // A read-only identity column is skipped by default (server assigns the
        // value) but retained when KeepIdentity is set.
        assert!(!bulk_column_is_target(&base_with_flags(identity_ro), false));
        assert!(bulk_column_is_target(&base_with_flags(identity_ro), true));

        // KeepIdentity only *adds* identity columns; it never drops a column that
        // was already a target on its own merits.
        assert!(bulk_column_is_target(
            &base_with_flags(identity_unknown),
            false
        ));
        assert!(bulk_column_is_target(
            &base_with_flags(identity_unknown),
            true
        ));

        // A non-identity read-only column is not resurrected by KeepIdentity.
        assert!(!bulk_column_is_target(&base_with_flags(read_only), true));
    }

    // A fixed, hand-written column list stands in for the server-provided
    // `MetaDataColumn` Display output so the SQL-string builder can be unit
    // tested without a live connection.
    const COLS: &str = "[id] int, [val] int";

    #[test]
    fn build_sql_no_options_no_hints_emits_no_with_clause() {
        // Empty options + empty hints must reproduce the plain statement that
        // `bulk_insert_columns` has always emitted.
        assert_eq!(
            build_insert_bulk_sql("t", COLS, SqlBulkCopyOptions::empty(), &[]),
            "INSERT BULK t ([id] int, [val] int)"
        );
    }

    #[test]
    fn build_sql_each_flag_emits_expected_keyword() {
        // `KeepIdentity` is deliberately absent: the `INSERT BULK` `WITH (...)`
        // grammar has no `KEEP_IDENTITY` keyword (it is a column-inclusion
        // concern), so only these four flags map to keywords.
        for (flag, keyword) in [
            (SqlBulkCopyOption::CheckConstraints, "CHECK_CONSTRAINTS"),
            (SqlBulkCopyOption::TableLock, "TABLOCK"),
            (SqlBulkCopyOption::KeepNulls, "KEEP_NULLS"),
            (SqlBulkCopyOption::FireTriggers, "FIRE_TRIGGERS"),
        ] {
            assert_eq!(
                build_insert_bulk_sql("t", COLS, flag.into(), &[]),
                format!("INSERT BULK t ([id] int, [val] int) WITH ({keyword})"),
                "flag {flag:?} did not emit {keyword}",
            );
        }
    }

    #[test]
    fn build_sql_keep_identity_emits_no_with_keyword() {
        // Regression guard: emitting `KEEP_IDENTITY` into the `WITH (...)` clause
        // is a syntax error against the TDS `INSERT BULK` statement (verified
        // against ADO.NET's `SqlBulkCopy` and go-mssqldb, neither of which emits
        // it). `KeepIdentity` alone must therefore produce no `WITH` clause at
        // all; the flag's effect is entirely in column selection.
        let sql = build_insert_bulk_sql("t", COLS, SqlBulkCopyOption::KeepIdentity.into(), &[]);
        assert_eq!(sql, "INSERT BULK t ([id] int, [val] int)", "got: {sql}");
        assert!(!sql.contains("KEEP_IDENTITY"), "got: {sql}");
    }

    #[test]
    fn build_sql_combined_flags_join_in_fixed_order() {
        // `KeepIdentity` contributes no keyword, so only TABLOCK/FIRE_TRIGGERS
        // appear even though it is set.
        let opts = SqlBulkCopyOption::KeepIdentity
            | SqlBulkCopyOption::TableLock
            | SqlBulkCopyOption::FireTriggers;

        assert_eq!(
            build_insert_bulk_sql("t", COLS, opts, &[]),
            "INSERT BULK t ([id] int, [val] int) WITH (TABLOCK, FIRE_TRIGGERS)"
        );
    }

    #[test]
    fn build_sql_all_flags() {
        // `all()` includes `KeepIdentity`, which emits nothing, so the keyword
        // list is the four real `WITH` options.
        let opts = SqlBulkCopyOptions::all();
        assert_eq!(
            build_insert_bulk_sql("t", COLS, opts, &[]),
            "INSERT BULK t ([id] int, [val] int) WITH (CHECK_CONSTRAINTS, TABLOCK, KEEP_NULLS, FIRE_TRIGGERS)"
        );
    }

    #[test]
    fn build_sql_order_hints_asc_and_desc() {
        // Plain column names are interpolated verbatim (like `columns`), not
        // re-bracketed, and the reference `ORDER(` has no space.
        let hints = [("id", SortOrder::Ascending), ("val", SortOrder::Descending)];
        assert_eq!(
            build_insert_bulk_sql("t", COLS, SqlBulkCopyOptions::empty(), &hints),
            "INSERT BULK t ([id] int, [val] int) WITH (ORDER(id ASC, val DESC))"
        );
    }

    #[test]
    fn build_sql_options_and_order_hints_combine() {
        let hints = [("id", SortOrder::Ascending)];
        assert_eq!(
            build_insert_bulk_sql("t", COLS, SqlBulkCopyOption::TableLock.into(), &hints),
            "INSERT BULK t ([id] int, [val] int) WITH (TABLOCK, ORDER(id ASC))"
        );
    }

    #[test]
    fn build_sql_order_hint_bracketed_name_not_double_escaped() {
        // Regression guard: order-hint column names are interpolated verbatim as
        // already-valid identifiers, exactly like `table`/`columns`. An
        // already-bracket-quoted name (which the validator accepts) must be
        // emitted as-is — NOT re-bracketed into `[[id]]]` or `[[my]]]]col]]]`.
        let hints = [
            ("[id]", SortOrder::Ascending),
            ("[my]]col]", SortOrder::Descending),
        ];
        assert_eq!(
            build_insert_bulk_sql("t", COLS, SqlBulkCopyOptions::empty(), &hints),
            "INSERT BULK t ([id] int, [val] int) WITH (ORDER([id] ASC, [my]]col] DESC))"
        );
    }

    #[test]
    fn build_sql_empty_hints_emits_no_order_clause() {
        let sql = build_insert_bulk_sql("t", COLS, SqlBulkCopyOption::TableLock.into(), &[]);
        assert!(!sql.contains("ORDER"), "got: {sql}");
        assert_eq!(sql, "INSERT BULK t ([id] int, [val] int) WITH (TABLOCK)");
    }

    #[test]
    fn build_sql_order_hint_column_names_are_validated_like_columns() {
        // The public API runs order-hint column names through the same guard as
        // the column list; confirm that guard rejects a stray `]`.
        assert!(validate_bulk_column_identifier("my]col").is_err());
        assert!(validate_bulk_column_identifier("[my]]col]").is_ok());
    }

    #[test]
    fn accepts_normal_column_identifiers() {
        for column in ["foo", "bar", "*", "[my col]", "[weird]]col]"] {
            assert!(
                validate_bulk_column_identifier(column).is_ok(),
                "expected column {column:?} to be accepted",
            );
        }
    }

    #[test]
    fn rejects_bad_column_identifiers() {
        // control character
        assert!(validate_bulk_column_identifier("foo\0bar").is_err());
        assert!(validate_bulk_column_identifier("foo\nbar").is_err());
        // lone / unbalanced closing bracket
        assert!(validate_bulk_column_identifier("foo]").is_err());
        assert!(validate_bulk_column_identifier("a]b").is_err());
    }

    #[test]
    fn accepts_normal_identifiers() {
        for table in [
            "Foo",
            "dbo.Foo",
            "##bulk_test",
            "#temp",
            "[my table]",
            "[dbo].[my table]",
            "[weird]]name]", // doubled `]]` escape inside brackets
        ] {
            assert!(
                validate_bulk_table_identifier(table).is_ok(),
                "expected {table:?} to be accepted",
            );
        }
    }

    #[test]
    fn rejects_control_characters() {
        assert!(validate_bulk_table_identifier("Foo\0bar").is_err());
        assert!(validate_bulk_table_identifier("Foo\nbar").is_err());
        assert!(validate_bulk_table_identifier("Foo\tbar").is_err());
    }

    #[test]
    fn rejects_unbalanced_closing_bracket() {
        assert!(validate_bulk_table_identifier("Foo]").is_err());
        assert!(validate_bulk_table_identifier("[my] table]").is_err());
        assert!(validate_bulk_table_identifier("a]b").is_err());
    }

    #[test]
    fn column_metadata_guards_reject_bad_identifiers() {
        // `column_metadata` interpolates `table`/`columns` into
        // `SELECT TOP 0 {columns} FROM {table}` and now validates both with the
        // same guards as `bulk_insert*`. A malformed table or column identifier
        // must be rejected before any SQL is built.
        assert!(validate_bulk_table_identifier("Foo]").is_err());
        assert!(validate_bulk_table_identifier("Foo\nbar").is_err());
        assert!(validate_bulk_column_identifier("id]").is_err());
        assert!(validate_bulk_column_identifier("col\0").is_err());
    }

    #[test]
    fn rejects_statement_breaking_identifiers() {
        // The guard must reject statement-breakers (`;`, quotes, `--`, `=`)
        // that would let an injected column/table escape the interpolated SQL.
        for bad in [
            "1; DROP TABLE Users--",
            "id = 1",
            "foo'bar",
            "foo\"bar",
            "foo--bar",
            "foo;bar",
        ] {
            assert!(
                validate_bulk_column_identifier(bad).is_err(),
                "expected column {bad:?} to be rejected",
            );
            assert!(
                validate_bulk_table_identifier(bad).is_err(),
                "expected table {bad:?} to be rejected",
            );
        }
    }

    #[test]
    fn accepts_star_and_bracketed_statement_breakers() {
        // `*` must stay valid as a whole column list (bulk_insert uses `&["*"]`),
        // and characters that would be statement-breakers outside brackets are
        // fine when properly bracket-quoted.
        assert!(validate_bulk_column_identifier("*").is_ok());
        assert!(validate_bulk_column_identifier("[weird;name]").is_ok());
        assert!(validate_bulk_table_identifier("[dbo].[my;table]").is_ok());
    }

    #[test]
    fn rejects_top_level_space_but_allows_it_inside_parens_and_brackets() {
        // A top-level space lets a single identifier split into multiple SQL
        // tokens without any otherwise-blocked character, so it is rejected.
        assert!(validate_bulk_table_identifier("t UNION SELECT name FROM sysobjects").is_err());
        assert!(validate_bulk_table_identifier("t WHERE 1=1").is_err());
        assert!(validate_bulk_column_identifier("a b").is_err());

        // A space is still fine inside a parameterized type's parens...
        assert!(super::validate_sql_identifier("db_type", "decimal(18, 4)").is_ok());
        // ...and inside a bracket-quoted name.
        assert!(validate_bulk_table_identifier("[my table]").is_ok());
        // The canonical no-space forms keep working.
        assert!(super::validate_sql_identifier("db_type", "decimal(10,2)").is_ok());
        assert!(super::validate_sql_identifier("db_type", "varchar(max)").is_ok());
    }

    #[test]
    fn rejects_delimiter_adjacent_token_splicing() {
        // A `]` or `)` is itself a SQL token boundary, so an attacker can splice
        // a new token onto one without any (now-blocked) top-level space. Both
        // forms must be rejected.
        assert!(
            validate_bulk_table_identifier("[RealTable]UNION(SELECT secret FROM users)").is_err()
        );
        assert!(validate_bulk_table_identifier("[t]UNION").is_err());
        assert!(validate_bulk_table_identifier("[t](1)").is_err());
        assert!(super::validate_sql_identifier("t", "foo(1)UNION(SELECT x)").is_err());
        assert!(super::validate_sql_identifier("t", "decimal(10,2)x").is_err());

        // ...while every legitimate multi-part / parameterized form still passes.
        assert!(validate_bulk_table_identifier("[dbo].[my table]").is_ok());
        assert!(validate_bulk_table_identifier("[db].[schema].[tbl]").is_ok());
        assert!(validate_bulk_table_identifier("[weird]]name]").is_ok());
        assert!(super::validate_sql_identifier("db_type", "decimal(18,4)").is_ok());
        assert!(super::validate_sql_identifier("db_type", "numeric(38, 38)").is_ok());
        assert!(super::validate_sql_identifier("db_type", "varchar(max)").is_ok());
    }

    #[test]
    fn rejects_unbalanced_closing_paren_and_top_level_comma() {
        // Order-hint columns are interpolated verbatim into `ORDER( ... )`, so a
        // value the guard accepts must not be able to close that paren early or
        // splice a second column: a lone trailing `)` (no matching `(`) and a
        // top-level comma are both rejected.
        assert!(validate_bulk_column_identifier("col)").is_err());
        assert!(validate_bulk_column_identifier(")").is_err());
        assert!(validate_bulk_column_identifier("a,b").is_err());
        assert!(validate_bulk_table_identifier("t)").is_err());
        assert!(super::validate_sql_identifier("db_type", "decimal(10,2))").is_err());

        // The symmetric openers must also be rejected: an unbalanced `(` never
        // closed, and an unterminated `[` that would swallow trailing SQL when
        // interpolated verbatim into `ORDER( ... )`.
        assert!(validate_bulk_column_identifier("a(b").is_err());
        assert!(validate_bulk_column_identifier("(").is_err());
        assert!(validate_bulk_column_identifier("[abc").is_err());
        assert!(validate_bulk_table_identifier("dbo.[my table").is_err());
        assert!(super::validate_sql_identifier("db_type", "decimal(10,2").is_err());

        // Balanced parens with an interior comma/space are still fine.
        assert!(super::validate_sql_identifier("db_type", "decimal(10,2)").is_ok());
        assert!(super::validate_sql_identifier("db_type", "numeric(18, 4)").is_ok());
        // A bracket-quoted name may still contain `)`/`,` literally.
        assert!(validate_bulk_column_identifier("[weird,name)]").is_ok());
    }
}
