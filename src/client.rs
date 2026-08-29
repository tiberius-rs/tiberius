mod auth;
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

use crate::tds::stream::ReceivedToken;
use crate::{
    result::ExecuteResult,
    tds::{
        codec::{self, IteratorJoin},
        stream::{QueryStream, TokenStream},
    },
    BulkLoadRequest, ColumnFlag, MetaDataColumn, SqlReadBytes, ToSql,
};
use codec::{BatchRequest, ColumnData, PacketHeader, RpcParam, RpcProcId, TokenRpcRequest};
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
    /// # Example
    ///
    /// ```
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
    /// # Example
    ///
    /// ```
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
    /// # Example
    ///
    /// ```
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
    /// # Example
    ///
    /// ```
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

        // Retrieve column metadata from the server, keeping only the updateable
        // columns as bulk targets (identity/computed columns are skipped).
        let mut columns: Vec<_> = self
            .column_metadata(table, columns)
            .await?
            .into_iter()
            .filter(|column| column.base.flags.contains(ColumnFlag::Updateable))
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
        let query = format!("INSERT BULK {} ({})", table, col_data);

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

    /// Closes this database connection explicitly.
    pub async fn close(self) -> crate::Result<()> {
        self.connection.close().await
    }

    pub(crate) fn rpc_params<'a>(query: impl Into<Cow<'a, str>>) -> Vec<RpcParam<'a>> {
        vec![
            RpcParam {
                name: Cow::Borrowed("stmt"),
                flags: BitFlags::empty(),
                value: ColumnData::String(Some(query.into())),
            },
            RpcParam {
                name: Cow::Borrowed("params"),
                flags: BitFlags::empty(),
                value: ColumnData::I32(Some(0)),
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
                value: param,
            });
        }

        if let Some(params) = rpc_params.iter_mut().find(|x| x.name == "params") {
            params.value = ColumnData::String(Some(param_str.into()));
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
}

/// Reject an obviously-malformed or dangerous bulk-insert table identifier.
///
/// The `table` argument of [`Client::bulk_insert`] / [`Client::bulk_insert_columns`]
/// is interpolated directly into the SQL batch because T-SQL does not allow
/// identifiers to be parameterized. This guard is cheap defense-in-depth — it
/// does NOT make untrusted input safe. It only rejects input that cannot be a
/// legitimate identifier:
///
/// - a NUL byte or any ASCII control character, and
/// - an unbalanced closing bracket `]` (per the T-SQL bracket-escaping rule a
///   literal `]` inside a `[...]` quoted identifier must be doubled as `]]`).
///
/// It deliberately does NOT try to quote or rewrite the identifier, so
/// multi-part names (`schema.table`), already-bracketed names (`[my table]`) and
/// temp tables (`##bulk_test`) keep working unchanged.
fn validate_bulk_table_identifier(table: &str) -> crate::Result<()> {
    validate_bulk_identifier("table", table)
}

/// Reject an obviously-malformed or dangerous bulk-insert `column` identifier.
///
/// Column names are interpolated into the metadata `SELECT` and `INSERT BULK`
/// column list exactly like `table`, so they get the same cheap
/// defense-in-depth check. See [`validate_bulk_table_identifier`].
fn validate_bulk_column_identifier(column: &str) -> crate::Result<()> {
    validate_bulk_identifier("column", column)
}

/// Shared implementation for the bulk `table`/`column` identifier guards.
/// `what` names the kind of identifier for the error message.
fn validate_bulk_identifier(what: &str, ident: &str) -> crate::Result<()> {
    if ident.chars().any(|c| c.is_ascii_control()) {
        return Err(crate::Error::BulkInput(
            format!("bulk insert {what} identifier must not contain NUL or control characters")
                .into(),
        ));
    }

    // Apply the T-SQL bracket rule: inside a `[...]` quoted identifier a literal
    // `]` must be doubled (`]]`); a single `]` closes the bracket. A `]` seen
    // outside of any bracket is unbalanced and rejected. Tracking bracket state
    // keeps legitimate names like `[dbo].[my table]` and `[weird]]name]`
    // working while catching stray closing brackets such as `Foo]`.
    let bytes = ident.as_bytes();
    let mut in_bracket = false;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'[' if !in_bracket => in_bracket = true,
            b']' if in_bracket => {
                if bytes.get(i + 1) == Some(&b']') {
                    // doubled `]]` escape: consume the pair, stay in the bracket
                    i += 2;
                    continue;
                }
                // single `]` closes the quoted identifier
                in_bracket = false;
            }
            b']' => {
                return Err(crate::Error::BulkInput(
                    format!("bulk insert {what} identifier contains an unbalanced `]` bracket")
                        .into(),
                ));
            }
            _ => {}
        }
        i += 1;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_bulk_column_identifier, validate_bulk_table_identifier};

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
}
