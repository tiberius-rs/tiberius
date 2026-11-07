use crate::tds::codec::{TokenError, TokenInfo};
use crate::tds::stream::{QueryItem, ReceivedToken, ResultMetadata};
use crate::{row::ColumnType, Column, Row};
use futures_util::{
    ready,
    stream::{BoxStream, Stream, StreamExt},
};
use std::{
    fmt::Debug,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

/// Everything a batch sends back, in the order the server sent it.
///
/// Unlike [`QueryItem`], this also carries the server's informational
/// messages (`PRINT`, `RAISERROR` below severity 11), the errors of
/// statements that failed while the batch went on, and the end of every
/// statement with the rows it affected. That is what a query tool needs to
/// show the output of a script the way SSMS or `sqlcmd` would.
#[derive(Debug)]
pub enum BatchItem {
    /// Information of the upcoming row data.
    Metadata(ResultMetadata),
    /// A single row of data.
    Row(Row),
    /// A statement finished. `rows` is the count the server reported, if it
    /// reported one (not under `SET NOCOUNT ON`).
    Done {
        /// Rows the statement affected or returned.
        rows: Option<u64>,
    },
    /// An informational message.
    Info(TokenInfo),
    /// A statement failed. Depending on the error the batch may go on.
    Error(TokenError),
}

/// A stream of [`BatchItem`]s, from [`Client::simple_batch`].
///
/// As with [`QueryStream`], poll it empty before using the client again.
///
/// [`Client::simple_batch`]: crate::Client::simple_batch
/// [`QueryStream`]: crate::QueryStream
pub struct BatchStream<'a> {
    token_stream: BoxStream<'a, crate::Result<ReceivedToken>>,
    columns: Option<Arc<Vec<Column>>>,
    result_set_index: Option<usize>,
    reported_error: bool,
}

impl<'a> Debug for BatchStream<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchStream").finish_non_exhaustive()
    }
}

impl<'a> BatchStream<'a> {
    pub(crate) fn new(token_stream: BoxStream<'a, crate::Result<ReceivedToken>>) -> Self {
        Self {
            token_stream,
            columns: None,
            result_set_index: None,
            reported_error: false,
        }
    }
}

impl<'a> Stream for BatchStream<'a> {
    type Item = crate::Result<BatchItem>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            let token = match ready!(this.token_stream.poll_next_unpin(cx)) {
                Some(Ok(token)) => token,
                // the token stream ends with the first server error, which
                // was already handed out as `BatchItem::Error`
                Some(Err(crate::Error::Server(_))) if this.reported_error => {
                    return Poll::Ready(None)
                }
                Some(Err(e)) => return Poll::Ready(Some(Err(e))),
                None => return Poll::Ready(None),
            };

            let item = match token {
                ReceivedToken::NewResultset(meta) => {
                    let columns = meta
                        .columns
                        .iter()
                        .map(|x| Column {
                            name: x.col_name.to_string(),
                            column_type: ColumnType::from(&x.base.ty),
                        })
                        .collect::<Vec<_>>();
                    let columns = Arc::new(columns);
                    this.columns = Some(columns.clone());
                    this.result_set_index = this.result_set_index.map(|i| i + 1);
                    let index = *this.result_set_index.get_or_insert(0);

                    match QueryItem::metadata(columns, index) {
                        QueryItem::Metadata(meta) => BatchItem::Metadata(meta),
                        QueryItem::Row(_) => unreachable!(),
                    }
                }
                ReceivedToken::Row(data) => {
                    let Some(columns) = this.columns.as_ref() else {
                        return Poll::Ready(Some(Err(crate::Error::Protocol(
                            "ROW token arrived before any column metadata".into(),
                        ))));
                    };
                    BatchItem::Row(Row {
                        columns: columns.clone(),
                        data,
                        result_index: this.result_set_index.unwrap_or(0),
                    })
                }
                // a procedure's own DONEPROC sums up statements already
                // reported through DONEINPROC
                ReceivedToken::Done(done) | ReceivedToken::DoneInProc(done) => BatchItem::Done {
                    rows: done.has_count().then(|| done.rows()),
                },
                ReceivedToken::Info(info) => BatchItem::Info(info),
                ReceivedToken::Error(error) => {
                    this.reported_error = true;
                    BatchItem::Error(error)
                }
                _ => continue,
            };

            return Poll::Ready(Some(Ok(item)));
        }
    }
}
