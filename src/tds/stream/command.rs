use crate::tds::stream::ReceivedToken;
use crate::{row::ColumnType, Column, Row};
use crate::{ColumnData, CommandResult, ResultMetadata};
use futures_util::{
    ready,
    stream::{BoxStream, Peekable, Stream, StreamExt, TryStreamExt},
};
use std::{
    fmt::Debug,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

/// A `Stream` of [`CommandItem`] values produced by executing a [`Command`].
///
/// Items can be result metadata, rows, a return status, return values (OUT
/// parameters) or a rows-affected count.
///
/// [`Command`]: crate::Command
///
/// # Example
///
/// ```no_run
/// # use std::env;
/// # use tiberius::Config;
/// # use tiberius::{Command, CommandItem};
/// # use futures_util::TryStreamExt;
/// # use tokio_util::compat::TokioAsyncWriteCompatExt;
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
/// cmd.bind_param("@zoo", "the zoo string prm");
/// cmd.bind_out_param("@bar", "bar");
/// let mut stream = cmd.exec(&mut client).await?;
///
/// while let Some(item) = stream.try_next().await? {
///     match item {
///         // our first item is the column data always
///         CommandItem::Metadata(meta) if meta.result_index() == 0 => {
///             // the first result column info can be handled here
///         }
///         // ... and from there on from 0..N rows
///         CommandItem::Row(row) if row.result_index() == 0 => {
///             let var: Option<i32> = row.get(0);
///         }
///         // the second result set returns first another metadata item
///         CommandItem::Metadata(meta) => {
///             // .. handling
///         }
///         // ...and, again, we get rows from the second resultset
///         CommandItem::Row(row) => {
///             let var: Option<i32> = row.get(0);
///         }
///         // check return status (returned always)
///         CommandItem::ReturnStatus(rs) => {
///             // .... do something
///         }
///         // collect OUT parameter values
///         CommandItem::ReturnValue(rv) => {
///             // .... do something, like push to a collection
///         }
///         // get affected row count
///         CommandItem::RowsAffected(ra) => {
///             // .... do something, like push to a collection
///         }
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
pub struct CommandStream<'a> {
    token_stream: Peekable<BoxStream<'a, crate::Result<ReceivedToken>>>,
    columns: Option<Arc<Vec<Column>>>,
    result_set_index: Option<usize>,
}

impl<'a> Debug for CommandStream<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandStream")
            .field(
                "token_stream",
                &"BoxStream<'a, crate::Result<ReceivedToken>>",
            )
            .finish()
    }
}

impl<'a> CommandStream<'a> {
    pub(crate) fn new(token_stream: BoxStream<'a, crate::Result<ReceivedToken>>) -> Self {
        Self {
            token_stream: token_stream.peekable(),
            columns: None,
            result_set_index: None,
        }
    }

    /// Collects all results from the command into memory, in the order they
    /// were produced by the server.
    pub async fn into_command_result(mut self) -> crate::Result<CommandResult> {
        let mut results: Vec<Vec<Row>> = Vec::new();
        let mut result: Option<Vec<Row>> = None;
        let mut return_status = 0;
        let mut return_values = Vec::new();
        let mut rows_affected = Vec::new();

        while let Some(item) = self.try_next().await? {
            match (item, &mut result) {
                (CommandItem::Row(row), None) => {
                    result = Some(vec![row]);
                }
                (CommandItem::Row(row), Some(ref mut result)) => result.push(row),
                (CommandItem::Metadata(_), None) => {
                    result = Some(Vec::new());
                }
                (CommandItem::Metadata(_), ref mut previous_result) => {
                    results.push(previous_result.take().unwrap());
                    result = None;
                }
                (CommandItem::ReturnStatus(rs), _) => return_status = rs,
                (CommandItem::ReturnValue(rv), _) => return_values.push(rv),
                (CommandItem::RowsAffected(rows), _) => rows_affected.push(rows),
            }
        }

        if let Some(result) = result {
            results.push(result);
        }

        Ok(CommandResult {
            return_code: return_status,
            return_values,
            query_results: results,
            rows_affected,
        })
    }

    /// Converts the stream into a stream of rows, dropping all other items.
    pub fn into_row_stream(self) -> BoxStream<'a, crate::Result<Row>> {
        let s = self.try_filter_map(|item| async {
            match item {
                CommandItem::Row(row) => Ok(Some(row)),
                _ => Ok(None),
            }
        });

        Box::pin(s)
    }
}

/// A single OUT parameter value returned by a [`Command`].
///
/// [`Command`]: crate::Command
#[derive(Debug)]
pub struct CommandReturnValue {
    pub(crate) name: String,
    pub(crate) ord: u16,
    pub(crate) data: ColumnData<'static>,
}

impl CommandReturnValue {
    /// The name of the OUT parameter this value corresponds to.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The ordinal of the OUT parameter as returned by the server.
    pub fn ordinal(&self) -> u16 {
        self.ord
    }

    /// A reference to the raw column data of the returned value.
    pub fn data(&self) -> &ColumnData<'static> {
        &self.data
    }
}

/// An item produced by a [`CommandStream`].
#[derive(Debug)]
pub enum CommandItem {
    /// A single row of data.
    Row(Row),
    /// Metadata describing the upcoming rows.
    Metadata(ResultMetadata),
    /// The return status from the server.
    ReturnStatus(u32),
    /// A return value, matching an OUT parameter.
    ReturnValue(CommandReturnValue),
    /// The number of rows affected by one of the statements ran on the server.
    RowsAffected(u64),
}

impl CommandItem {
    pub(crate) fn metadata(columns: Arc<Vec<Column>>, result_index: usize) -> Self {
        Self::Metadata(ResultMetadata {
            columns,
            result_index,
        })
    }

    /// Returns a reference to the metadata, if the item is of a correct variant.
    pub fn as_metadata(&self) -> Option<&ResultMetadata> {
        match self {
            CommandItem::Metadata(ref metadata) => Some(metadata),
            _ => None,
        }
    }

    /// Returns a reference to the row, if the item is of a correct variant.
    pub fn as_row(&self) -> Option<&Row> {
        match self {
            CommandItem::Row(ref row) => Some(row),
            _ => None,
        }
    }

    /// Returns the metadata, if the item is of a correct variant.
    pub fn into_metadata(self) -> Option<ResultMetadata> {
        match self {
            CommandItem::Metadata(metadata) => Some(metadata),
            _ => None,
        }
    }

    /// Returns the row, if the item is of a correct variant.
    pub fn into_row(self) -> Option<Row> {
        match self {
            CommandItem::Row(row) => Some(row),
            _ => None,
        }
    }

    /// Returns the return status, if the item is of a correct variant.
    pub fn as_return_status(&self) -> Option<u32> {
        match self {
            CommandItem::ReturnStatus(rs) => Some(*rs),
            _ => None,
        }
    }

    /// Returns a reference to the return value, if the item is of a correct variant.
    pub fn as_return_value(&self) -> Option<&CommandReturnValue> {
        match self {
            CommandItem::ReturnValue(rv) => Some(rv),
            _ => None,
        }
    }

    /// Returns the return value, if the item is of a correct variant.
    pub fn into_return_value(self) -> Option<CommandReturnValue> {
        match self {
            CommandItem::ReturnValue(rv) => Some(rv),
            _ => None,
        }
    }
}

impl<'a> Stream for CommandStream<'a> {
    type Item = crate::Result<CommandItem>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            let token = match ready!(this.token_stream.poll_next_unpin(cx)) {
                Some(res) => res?,
                None => return Poll::Ready(None),
            };

            return match token {
                ReceivedToken::NewResultset(meta) => {
                    let column_meta = meta
                        .columns
                        .iter()
                        .map(|x| Column {
                            name: x.col_name.to_string(),
                            column_type: ColumnType::from(&x.base.ty),
                        })
                        .collect::<Vec<_>>();

                    let column_meta = Arc::new(column_meta);
                    this.columns = Some(column_meta.clone());

                    this.result_set_index = this.result_set_index.map(|i| i + 1);

                    let query_item =
                        CommandItem::metadata(column_meta, *this.result_set_index.get_or_insert(0));

                    Poll::Ready(Some(Ok(query_item)))
                }
                ReceivedToken::Row(data) => {
                    let Some(columns) = this.columns.as_ref() else {
                        return Poll::Ready(Some(Err(crate::Error::Protocol(
                            "ROW token arrived before any column metadata".into(),
                        ))));
                    };
                    let columns = columns.clone();
                    let result_index = this.result_set_index.unwrap_or(0);

                    let row = Row {
                        columns,
                        data,
                        result_index,
                    };

                    Poll::Ready(Some(Ok(CommandItem::Row(row))))
                }
                ReceivedToken::ReturnStatus(rs) => {
                    Poll::Ready(Some(Ok(CommandItem::ReturnStatus(rs))))
                }
                ReceivedToken::ReturnValue(rv) => {
                    Poll::Ready(Some(Ok(CommandItem::ReturnValue(CommandReturnValue {
                        name: rv.param_name,
                        ord: rv.param_ordinal,
                        data: rv.value,
                    }))))
                }
                ReceivedToken::DoneProc(done) if done.is_final() => continue,
                ReceivedToken::DoneProc(done) => {
                    Poll::Ready(Some(Ok(CommandItem::RowsAffected(done.rows()))))
                }
                ReceivedToken::DoneInProc(done) => {
                    Poll::Ready(Some(Ok(CommandItem::RowsAffected(done.rows()))))
                }
                ReceivedToken::Done(done) => {
                    Poll::Ready(Some(Ok(CommandItem::RowsAffected(done.rows()))))
                }
                _ => continue,
            };
        }
    }
}
