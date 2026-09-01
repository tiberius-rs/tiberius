use std::borrow::Cow;

use enumflags2::BitFlags;
use futures_util::io::{AsyncRead, AsyncWrite};

use crate::{
    tds::{
        codec::{RpcParam, RpcStatus::ByRefValue, RpcValue, TypeInfoTvp},
        stream::{CommandStream, TokenStream},
    },
    Client, ColumnData, IntoSql,
};

#[doc(inline)]
pub use tiberius_macros::TableValueRow;

/// A structure that represents a single row of a table-valued parameter (TVP)
/// implements this trait.
///
/// It can be derived with `#[derive(TableValueRow)]` for structs with named
/// fields.
pub trait TableValueRow<'a> {
    /// Binds this row's field values. Called by [`Command`] before making the
    /// call to the server; implementations must call
    /// [`SqlTableDataRow::add_field`] once per column, in column order.
    fn bind_fields(&self, data_row: &mut SqlTableDataRow<'a>);
    /// The database type name that represents this TVP, e.g. `dbo.MyType`.
    fn get_db_type() -> &'static str;
}

/// A collection of [`TableValueRow`] values that can be bound as a
/// table-valued parameter. Implemented for any `IntoIterator` of rows.
pub trait TableValue<'a> {
    /// Converts this collection into the internal table data representation.
    fn into_sql(self) -> SqlTableData<'a>;
}

impl<'a, R, C> TableValue<'a> for C
where
    R: TableValueRow<'a> + 'a,
    C: IntoIterator<Item = R>,
{
    fn into_sql(self) -> SqlTableData<'a> {
        let mut data = Vec::new();
        for row in self.into_iter() {
            let mut data_row = SqlTableDataRow::new();
            row.bind_fields(&mut data_row);
            data.push(data_row);
        }

        SqlTableData {
            rows: data,
            db_type: R::get_db_type(),
        }
    }
}

/// A remote command (stored procedure or user-defined function) with bound
/// parameters, executed by name via an RPC request.
#[derive(Debug)]
pub struct Command<'a> {
    name: Cow<'a, str>,
    // The server rejects repeated parameter names, so uniqueness is not checked here.
    params: Vec<CommandParam<'a>>,
}

#[derive(Debug)]
struct CommandParam<'a> {
    name: Cow<'a, str>,
    out: bool,
    data: CommandParamData<'a>,
}

#[derive(Debug)]
enum CommandParamData<'a> {
    Scalar(ColumnData<'a>),
    Table(SqlTableData<'a>),
}

/// The internal representation of a table-valued parameter's data.
#[derive(Debug)]
pub struct SqlTableData<'a> {
    rows: Vec<SqlTableDataRow<'a>>,
    db_type: &'a str,
}

/// A single row of a table-valued parameter, used by [`TableValueRow`]
/// implementations to bind column values.
#[derive(Debug)]
pub struct SqlTableDataRow<'a> {
    col_data: Vec<ColumnData<'a>>,
}

impl<'a> SqlTableDataRow<'a> {
    fn new() -> SqlTableDataRow<'a> {
        SqlTableDataRow {
            col_data: Vec::new(),
        }
    }

    /// Adds a field value to this TVP row. Must be called once per column; the
    /// values are sent to the server in call order.
    pub fn add_field(&mut self, data: impl IntoSql<'a> + 'a) {
        self.col_data.push(data.into_sql());
    }
}

impl<'a> Command<'a> {
    /// Constructs a new command with the given procedure or function name.
    pub fn new(proc_name: impl Into<Cow<'a, str>>) -> Self {
        Self {
            name: proc_name.into(),
            params: Vec::new(),
        }
    }

    /// Binds a scalar input parameter with the given name.
    pub fn bind_param(&mut self, name: impl Into<Cow<'a, str>>, data: impl IntoSql<'a> + 'a) {
        self.params.push(CommandParam {
            name: name.into(),
            out: false,
            data: CommandParamData::Scalar(data.into_sql()),
        });
    }

    /// Binds a by-ref (OUT) scalar parameter. The returned value can be found by
    /// the same name in the [`CommandResult`] returned values.
    ///
    /// [`CommandResult`]: crate::CommandResult
    pub fn bind_out_param(&mut self, name: impl Into<Cow<'a, str>>, data: impl IntoSql<'a> + 'a) {
        self.params.push(CommandParam {
            name: name.into(),
            out: true,
            data: CommandParamData::Scalar(data.into_sql()),
        });
    }

    /// Binds a table-valued parameter. The provided argument must implement
    /// [`TableValue`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::env;
    /// # use tiberius::Config;
    /// # use tiberius::{numeric::Numeric, Command, TableValueRow};
    /// # use tokio_util::compat::TokioAsyncWriteCompatExt;
    /// #[derive(TableValueRow)]
    /// struct SomeGeoList {
    ///     eid: i32,
    ///     lat: Numeric,
    ///     lon: Numeric,
    /// }
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let c_str = env::var("TIBERIUS_TEST_CONNECTION_STRING").unwrap_or(
    /// #     "server=tcp:localhost,1433;integratedSecurity=true;TrustServerCertificate=true".to_owned(),
    /// # );
    /// # let config = Config::from_ado_string(&c_str)?;
    /// # let tcp = tokio::net::TcpStream::connect(config.get_addr()).await?;
    /// # tcp.set_nodelay(true)?;
    /// # let client = tiberius::Client::connect(config, tcp.compat_write()).await?;
    /// let r1 = SomeGeoList {
    ///     eid: 1,
    ///     lat: Numeric::new_with_scale(10, 6),
    ///     lon: Numeric::new_with_scale(14, 6),
    /// };
    /// let r2 = SomeGeoList {
    ///     eid: 4,
    ///     lat: Numeric::new_with_scale(101, 6),
    ///     lon: Numeric::new_with_scale(142, 6),
    /// };
    ///
    /// let tbl = vec![r1, r2];
    ///
    /// let mut cmd = Command::new("dbo.usp_TheGeoProcedure");
    /// cmd.bind_table("@table", tbl);
    /// # Ok(())
    /// # }
    /// ```
    pub fn bind_table(&mut self, name: impl Into<Cow<'a, str>>, data: impl TableValue<'a> + 'a) {
        self.params.push(CommandParam {
            name: name.into(),
            out: false,
            data: CommandParamData::Table(data.into_sql()),
        });
    }

    /// The same as [`bind_table`](Self::bind_table), but overrides the database
    /// type name used for the TVP.
    pub fn bind_table_with_dbtype(
        &mut self,
        name: impl Into<Cow<'a, str>>,
        db_type: &'a str,
        data: impl TableValue<'a> + 'a,
    ) {
        self.params.push(CommandParam {
            name: name.into(),
            out: false,
            data: CommandParamData::Table(SqlTableData {
                db_type,
                ..data.into_sql()
            }),
        });
    }

    /// Executes the command on the server, returning a [`CommandStream`] that
    /// can be collected into a [`CommandResult`] for convenience.
    ///
    /// [`CommandResult`]: crate::CommandResult
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
    /// # Ok(())
    /// # }
    /// ```
    pub async fn exec<'b, S>(self, client: &'b mut Client<S>) -> crate::Result<CommandStream<'b>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let rpc_params = Command::build_rpc_params(self.params, client).await?;

        client.connection.flush_stream().await?;
        client.rpc_run_command(self.name, rpc_params).await?;

        let ts = TokenStream::new(&mut client.connection);
        let result = CommandStream::new(ts.try_unfold());

        Ok(result)
    }

    async fn build_rpc_params<'b, S>(
        cmd_params: Vec<CommandParam<'a>>,
        client: &'b mut Client<S>,
    ) -> crate::Result<Vec<RpcParam<'a>>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut rpc_params = Vec::new();
        for p in cmd_params.into_iter() {
            let rpc_val = match p.data {
                CommandParamData::Scalar(col) => RpcValue::Scalar(col),
                CommandParamData::Table(t) => {
                    let type_info_tvp = TypeInfoTvp::new(
                        t.db_type,
                        t.rows.into_iter().map(|r| r.col_data).collect(),
                    );
                    // Resolve the TVP column layout from the server.
                    let cols_metadata = client
                        .query_run_for_metadata(format!(
                            "DECLARE @P AS {};SELECT TOP 0 * FROM @P",
                            t.db_type
                        ))
                        .await?;
                    RpcValue::Table(if let Some(cm) = cols_metadata {
                        type_info_tvp.with_metadata(cm)
                    } else {
                        type_info_tvp
                    })
                }
            };
            let rpc_param = RpcParam {
                name: p.name,
                flags: if p.out {
                    BitFlags::from_flag(ByRefValue)
                } else {
                    BitFlags::empty()
                },
                value: rpc_val,
            };
            rpc_params.push(rpc_param);
        }
        Ok(rpc_params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestRow;

    impl<'a> TableValueRow<'a> for TestRow {
        fn bind_fields(&self, row: &mut SqlTableDataRow<'a>) {
            row.add_field(1i32);
        }

        fn get_db_type() -> &'static str {
            "default.Type"
        }
    }

    #[test]
    fn bind_table_with_dbtype_uses_the_explicit_db_type() {
        // The explicit db_type argument must override the row's own get_db_type().
        let mut cmd = Command::new("proc");
        cmd.bind_table_with_dbtype("@tvp", "explicit.Type", vec![TestRow]);

        assert_eq!(cmd.params.len(), 1);
        assert_eq!(cmd.params[0].name, "@tvp");
        match &cmd.params[0].data {
            CommandParamData::Table(t) => assert_eq!(t.db_type, "explicit.Type"),
            other => panic!("expected a table parameter, got {other:?}"),
        }
    }

    #[test]
    fn bind_table_uses_the_rows_db_type() {
        let mut cmd = Command::new("proc");
        cmd.bind_table("@tvp", vec![TestRow]);

        match &cmd.params[0].data {
            CommandParamData::Table(t) => assert_eq!(t.db_type, "default.Type"),
            other => panic!("expected a table parameter, got {other:?}"),
        }
    }
}
