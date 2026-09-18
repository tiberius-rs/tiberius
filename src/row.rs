use crate::{
    error::Error,
    tds::codec::{ColumnData, FixedLenType, TokenRow, TypeInfo, VarLenType},
    FromSql,
};
use std::{fmt::Display, sync::Arc};

/// A column of data from a query.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Column {
    pub(crate) name: String,
    pub(crate) column_type: ColumnType,
}

impl Column {
    /// Construct a new Column.
    pub fn new(name: String, column_type: ColumnType) -> Self {
        Self { name, column_type }
    }

    /// The name of the column.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The type of the column.
    pub fn column_type(&self) -> ColumnType {
        self.column_type
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// The type of the column.
pub enum ColumnType {
    /// The column doesn't have a specified type.
    Null,
    /// A bit or boolean value.
    Bit,
    /// An 8-bit integer value.
    Int1,
    /// A 16-bit integer value.
    Int2,
    /// A 32-bit integer value.
    Int4,
    /// A 64-bit integer value.
    Int8,
    /// A 32-bit datetime value.
    Datetime4,
    /// A 32-bit floating point value.
    Float4,
    /// A 64-bit floating point value.
    Float8,
    /// Money value.
    Money,
    /// A TDS 7.2 datetime value.
    Datetime,
    /// A 32-bit money value.
    Money4,
    /// A unique identifier, UUID.
    Guid,
    /// N-bit integer value (variable).
    Intn,
    /// A bit value in a variable-length type.
    Bitn,
    /// A decimal value (same as `Numericn`).
    Decimaln,
    /// A numeric value (same as `Decimaln`).
    Numericn,
    /// A n-bit floating point value.
    Floatn,
    /// A n-bit datetime value (TDS 7.2).
    Datetimen,
    /// A n-bit date value (TDS 7.3).
    Daten,
    /// A n-bit time value (TDS 7.3).
    Timen,
    /// A n-bit datetime2 value (TDS 7.3).
    Datetime2,
    /// A n-bit datetime value with an offset (TDS 7.3).
    DatetimeOffsetn,
    /// A variable binary value.
    BigVarBin,
    /// A large variable string value.
    BigVarChar,
    /// A binary value.
    BigBinary,
    /// A string value.
    BigChar,
    /// A variable string value with UTF-16 encoding.
    NVarchar,
    /// A string value with UTF-16 encoding.
    NChar,
    /// A XML value.
    Xml,
    /// User-defined type.
    Udt,
    /// A text value (deprecated).
    Text,
    /// A image value (deprecated).
    Image,
    /// A text value with UTF-16 encoding (deprecated).
    NText,
    /// An SQL variant type.
    SSVariant,
}

impl From<&TypeInfo> for ColumnType {
    fn from(ti: &TypeInfo) -> Self {
        match ti {
            TypeInfo::FixedLen(flt) => match flt {
                FixedLenType::Int1 => Self::Int1,
                FixedLenType::Bit => Self::Bit,
                FixedLenType::Int2 => Self::Int2,
                FixedLenType::Int4 => Self::Int4,
                FixedLenType::Datetime4 => Self::Datetime4,
                FixedLenType::Float4 => Self::Float4,
                FixedLenType::Money => Self::Money,
                FixedLenType::Datetime => Self::Datetime,
                FixedLenType::Float8 => Self::Float8,
                FixedLenType::Money4 => Self::Money4,
                FixedLenType::Int8 => Self::Int8,
                FixedLenType::Null => Self::Null,
            },
            TypeInfo::VarLenSized(cx) => match cx.r#type() {
                VarLenType::Guid => Self::Guid,
                VarLenType::Intn => match cx.len() {
                    1 => Self::Int1,
                    2 => Self::Int2,
                    4 => Self::Int4,
                    8 => Self::Int8,
                    _ => Self::Intn,
                },
                VarLenType::Bitn => Self::Bitn,
                VarLenType::Decimaln => Self::Decimaln,
                VarLenType::Numericn => Self::Numericn,
                VarLenType::Floatn => match cx.len() {
                    4 => Self::Float4,
                    8 => Self::Float8,
                    _ => Self::Floatn,
                },
                VarLenType::Money => Self::Money,
                VarLenType::Datetimen => Self::Datetimen,
                #[cfg(feature = "tds73")]
                VarLenType::Daten => Self::Daten,
                #[cfg(feature = "tds73")]
                VarLenType::Timen => Self::Timen,
                #[cfg(feature = "tds73")]
                VarLenType::Datetime2 => Self::Datetime2,
                #[cfg(feature = "tds73")]
                VarLenType::DatetimeOffsetn => Self::DatetimeOffsetn,
                VarLenType::BigVarBin => Self::BigVarBin,
                VarLenType::BigVarChar => Self::BigVarChar,
                VarLenType::BigBinary => Self::BigBinary,
                VarLenType::BigChar => Self::BigChar,
                VarLenType::NVarchar => Self::NVarchar,
                VarLenType::NChar => Self::NChar,
                VarLenType::Xml => Self::Xml,
                VarLenType::Udt => Self::Udt,
                VarLenType::Text => Self::Text,
                VarLenType::Image => Self::Image,
                VarLenType::NText => Self::NText,
                VarLenType::SSVariant => Self::SSVariant,
            },
            TypeInfo::VarLenSizedPrecision { ty, .. } => match ty {
                VarLenType::Guid => Self::Guid,
                VarLenType::Intn => Self::Intn,
                VarLenType::Bitn => Self::Bitn,
                VarLenType::Decimaln => Self::Decimaln,
                VarLenType::Numericn => Self::Numericn,
                VarLenType::Floatn => Self::Floatn,
                VarLenType::Money => Self::Money,
                VarLenType::Datetimen => Self::Datetimen,
                #[cfg(feature = "tds73")]
                VarLenType::Daten => Self::Daten,
                #[cfg(feature = "tds73")]
                VarLenType::Timen => Self::Timen,
                #[cfg(feature = "tds73")]
                VarLenType::Datetime2 => Self::Datetime2,
                #[cfg(feature = "tds73")]
                VarLenType::DatetimeOffsetn => Self::DatetimeOffsetn,
                VarLenType::BigVarBin => Self::BigVarBin,
                VarLenType::BigVarChar => Self::BigVarChar,
                VarLenType::BigBinary => Self::BigBinary,
                VarLenType::BigChar => Self::BigChar,
                VarLenType::NVarchar => Self::NVarchar,
                VarLenType::NChar => Self::NChar,
                VarLenType::Xml => Self::Xml,
                VarLenType::Udt => Self::Udt,
                VarLenType::Text => Self::Text,
                VarLenType::Image => Self::Image,
                VarLenType::NText => Self::NText,
                VarLenType::SSVariant => Self::SSVariant,
            },
            TypeInfo::Xml { .. } => Self::Xml,
            TypeInfo::Udt(_) => Self::Udt,
        }
    }
}

/// A row of data from a query.
///
/// Data can be accessed either by copying through [`get`] or [`try_get`]
/// methods, or moving by value using the [`IntoIterator`] implementation.
///
/// ```
/// # use tiberius::{Config, FromSqlOwned};
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
/// // by-reference
/// let row = client
///     .query("SELECT @P1 AS col1", &[&"test"])
///     .await?
///     .into_row()
///     .await?
///     .unwrap();
///
/// assert_eq!(Some("test"), row.get("col1"));
///
/// // ...or by-value
/// let row = client
///     .query("SELECT @P1 AS col1", &[&"test"])
///     .await?
///     .into_row()
///     .await?
///     .unwrap();
///
/// for val in row.into_iter() {
///     assert_eq!(
///         Some(String::from("test")),
///         String::from_sql_owned(val)?
///     )
/// }
/// # Ok(())
/// # }
/// ```
///
/// [`get`]: #method.get
/// [`try_get`]: #method.try_get
/// [`IntoIterator`]: #impl-IntoIterator
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Row {
    pub(crate) columns: Arc<Vec<Column>>,
    pub(crate) data: TokenRow<'static>,
    pub(crate) result_index: usize,
}

/// A type that can address a column within a [`Row`], either by its zero-based
/// position (`usize`) or by name (`&str`).
///
/// Implement this for a custom column identifier (for example a generated
/// column-name enum) to index rows with it via [`Row::get`]/[`Row::try_get`].
pub trait QueryIdx
where
    Self: Display,
{
    /// Resolves this index to the column's zero-based position in `row`, or
    /// `None` if it does not name/point to a column in the row.
    fn idx(&self, row: &Row) -> Option<usize>;
}

impl QueryIdx for usize {
    fn idx(&self, row: &Row) -> Option<usize> {
        (*self < row.columns.len()).then_some(*self)
    }
}

impl QueryIdx for &str {
    fn idx(&self, row: &Row) -> Option<usize> {
        // Prefer an exact column-name match so a column literally named `r#...`
        // (or `type`) resolves to itself.
        if let Some(p) = row.columns.iter().position(|c| c.name() == *self) {
            return Some(p);
        }
        // Fallback: allow a Rust raw identifier (`r#type`) to match the plain SQL
        // name (`type`) when no exact column exists.
        self.strip_prefix("r#")
            .and_then(|n| row.columns.iter().position(|c| c.name() == n))
    }
}

impl Row {
    /// Columns defining the row data. Columns listed here are in the same order
    /// as the resulting data.
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
    /// let row = client
    ///     .query("SELECT 1 AS foo, 2 AS bar", &[])
    ///     .await?
    ///     .into_row()
    ///     .await?
    ///     .unwrap();
    ///
    /// assert_eq!("foo", row.columns()[0].name());
    /// assert_eq!("bar", row.columns()[1].name());
    /// # Ok(())
    /// # }
    /// ```
    pub fn columns(&self) -> &[Column] {
        &self.columns
    }

    /// Return an iterator over row column-value pairs.
    pub fn cells(&self) -> impl Iterator<Item = (&Column, &ColumnData<'static>)> {
        self.columns().iter().zip(self.data.iter())
    }

    /// The result set number, starting from zero and increasing if the stream
    /// has results from more than one query.
    pub fn result_index(&self) -> usize {
        self.result_index
    }

    /// Returns the number of columns in the row.
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
    /// let row = client
    ///     .query("SELECT 1, 2", &[])
    ///     .await?
    ///     .into_row()
    ///     .await?
    ///     .unwrap();
    ///
    /// assert_eq!(2, row.len());
    /// # Ok(())
    /// # }
    /// ```
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Retrieve a column value for a given column index, which can either be
    /// the zero-indexed position or the name of the column.
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
    /// let row = client
    ///     .query("SELECT @P1 AS col1", &[&1i32])
    ///     .await?
    ///     .into_row()
    ///     .await?
    ///     .unwrap();
    ///
    /// assert_eq!(Some(1i32), row.get(0));
    /// assert_eq!(Some(1i32), row.get("col1"));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Panics
    ///
    /// - The requested type conversion (SQL->Rust) is not possible.
    /// - The given index is out of bounds (column does not exist).
    ///
    /// Use [`try_get`] for a non-panicking version of the function.
    ///
    /// [`try_get`]: #method.try_get
    #[track_caller]
    pub fn get<'a, R, I>(&'a self, idx: I) -> Option<R>
    where
        R: FromSql<'a>,
        I: QueryIdx,
    {
        self.try_get(idx).unwrap()
    }

    /// Retrieve a column's value for a given column index.
    ///
    /// # Errors
    ///
    /// Returns an error if the given index does not name a column in the row, or
    /// if the stored value cannot be converted into the requested Rust type `R`.
    #[track_caller]
    pub fn try_get<'a, R, I>(&'a self, idx: I) -> crate::Result<Option<R>>
    where
        R: FromSql<'a>,
        I: QueryIdx,
    {
        let data = self.get_column_data(idx)?;

        R::from_sql(data)
    }

    /// Retrieve a column's data for a given column index.
    ///
    /// # Errors
    ///
    /// Returns an error if the given index does not name a column in the row, or
    /// if the row carries fewer cells than columns (a malformed `ROW`/`NBCROW`).
    #[track_caller]
    pub fn get_column_data<I>(&self, idx: I) -> crate::Result<&ColumnData<'static>>
    where
        I: QueryIdx,
    {
        let idx = idx.idx(self).ok_or_else(|| {
            Error::Conversion(format!("Could not find column with index {}", idx).into())
        })?;

        // `idx` was validated against the column metadata; the cell should exist,
        // but a malformed ROW/NBCROW with fewer cells than columns must not
        // panic here — return an error instead of unwrapping.
        self.data.get(idx).ok_or_else(|| {
            Error::Protocol(format!("row has no data for column index {idx}").into())
        })
    }

    /// Consumes the row, returning the underlying [`TokenRow`] holding the raw
    /// column data as received from the server.
    ///
    /// This is useful when direct access to the raw [`ColumnData`] values is
    /// needed instead of converting them through [`get`] or [`try_get`].
    ///
    /// [`get`]: #method.get
    /// [`try_get`]: #method.try_get
    pub fn into_token_row(self) -> TokenRow<'static> {
        self.data
    }

    /// Creates a [`RowBuilder`] for assembling a `Row` outside of a query.
    ///
    /// A `Row` returned from a query is normally built by the driver from data
    /// received over the wire, and its fields are not otherwise accessible. This
    /// entry point exists so callers can construct a `Row` directly — primarily
    /// to unit-test functions that take a [`Row`] or `&[Row]` without needing a
    /// live database connection.
    ///
    /// See [`RowBuilder`] for a full example.
    pub fn builder() -> RowBuilder {
        RowBuilder::default()
    }
}

/// A builder for constructing a [`Row`] outside of a query.
///
/// This is primarily intended for unit tests that exercise functions taking a
/// [`Row`] or `&[Row]` without a live database connection. Obtain one via
/// [`Row::builder`].
///
/// Each [`column`] call appends a column's metadata together with its value, so
/// the column count and the value count can never drift out of sync. The row is
/// finished with [`build`].
///
/// # Example
///
/// ```
/// use tiberius::{ColumnData, ColumnType, Row};
///
/// let row = Row::builder()
///     .column("id", ColumnType::Int4, ColumnData::I32(Some(1)))
///     .column(
///         "name",
///         ColumnType::NVarchar,
///         ColumnData::String(Some("Alice".into())),
///     )
///     .column("age", ColumnType::Int4, ColumnData::I32(None))
///     .build();
///
/// assert_eq!(Some(1), row.get::<i32, _>("id"));
/// assert_eq!(Some("Alice"), row.get::<&str, _>(1));
/// assert_eq!(None, row.get::<i32, _>("age"));
/// ```
///
/// [`column`]: RowBuilder::column
/// [`build`]: RowBuilder::build
#[derive(Debug, Default)]
pub struct RowBuilder {
    columns: Vec<Column>,
    data: TokenRow<'static>,
    result_index: usize,
}

impl RowBuilder {
    /// Appends a column and its value to the row being built.
    ///
    /// `name` is the column name used for by-name lookups, `column_type` is the
    /// [`ColumnType`] reported by [`Column::column_type`], and `value` holds the
    /// cell's [`ColumnData`]. Columns keep the order in which they are added.
    ///
    /// `column_type` is stored as-is and is *not* checked against `value`: the
    /// value accessors ([`Row::get`]/[`Row::try_get`]) dispatch on the
    /// [`ColumnData`] variant alone, so a mismatched `column_type` only affects
    /// what [`Column::column_type`] reports. Keeping the two consistent is the
    /// caller's responsibility.
    pub fn column(
        mut self,
        name: impl Into<String>,
        column_type: ColumnType,
        value: ColumnData<'static>,
    ) -> Self {
        self.columns.push(Column::new(name.into(), column_type));
        self.data.push(value);
        self
    }

    /// Sets the result-set index reported by [`Row::result_index`].
    ///
    /// Defaults to `0` when not called.
    pub fn result_index(mut self, result_index: usize) -> Self {
        self.result_index = result_index;
        self
    }

    /// Consumes the builder and returns the assembled [`Row`].
    pub fn build(self) -> Row {
        Row {
            columns: Arc::new(self.columns),
            data: self.data,
            result_index: self.result_index,
        }
    }
}

impl IntoIterator for Row {
    type Item = ColumnData<'static>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    fn make_row() -> Row {
        let columns = Arc::new(vec![
            Column::new("foo".to_string(), ColumnType::Int4),
            Column::new("type".to_string(), ColumnType::Int4),
        ]);

        let mut data = TokenRow::new();
        data.push(ColumnData::I32(Some(1)));
        data.push(ColumnData::I32(Some(2)));

        Row {
            columns,
            data,
            result_index: 0,
        }
    }

    #[test]
    fn result_index_reflects_the_field() {
        // `result_index()` returns the row's stored result index.
        let columns = Arc::new(vec![Column::new("c".to_string(), ColumnType::Int4)]);
        let mut data = TokenRow::new();
        data.push(ColumnData::I32(Some(1)));
        let row = Row {
            columns,
            data,
            result_index: 3,
        };
        assert_eq!(row.result_index(), 3);
    }

    // Regression test for #211: an out-of-range usize index must not panic.
    #[test]
    fn try_get_out_of_range_index_returns_none() {
        let row = make_row();

        assert_eq!(None, 2usize.idx(&row));
        assert_eq!(Some(0), 0usize.idx(&row));

        let value: crate::Result<Option<i32>> = row.try_get(5usize);
        assert!(value.is_err());
    }

    // Regression test for #382: a raw-identifier column name (`r#type`) must
    // match the plain SQL column name (`type`).
    #[test]
    fn raw_identifier_column_name_matches() {
        let row = make_row();

        assert_eq!(Some(1), "type".idx(&row));
        assert_eq!(Some(1), "r#type".idx(&row));
        assert_eq!(Some(0), "r#foo".idx(&row));
        assert_eq!(None, "r#missing".idx(&row));

        assert_eq!(Some(2i32), row.get::<i32, _>("r#type"));
    }

    // A column literally named `r#type` alongside a `type` column must each
    // resolve to themselves: the exact match wins before the r# fallback.
    #[test]
    fn literal_raw_prefixed_column_wins_over_fallback() {
        let columns = Arc::new(vec![
            Column::new("type".to_string(), ColumnType::Int4),
            Column::new("r#type".to_string(), ColumnType::Int4),
        ]);

        let mut data = TokenRow::new();
        data.push(ColumnData::I32(Some(1)));
        data.push(ColumnData::I32(Some(2)));

        let row = Row {
            columns,
            data,
            result_index: 0,
        };

        // Exact match: `type` -> the "type" column (index 0).
        assert_eq!(Some(0), "type".idx(&row));
        // Exact match: `r#type` -> the literal "r#type" column (index 1),
        // NOT the "type" column via the strip fallback.
        assert_eq!(Some(1), "r#type".idx(&row));
    }

    // A column literally named `r#foo` (with no plain `foo` column) resolves to
    // itself via the exact match; the fallback is never needed.
    #[test]
    fn literal_raw_prefixed_column_exact_match() {
        let columns = Arc::new(vec![Column::new("r#foo".to_string(), ColumnType::Int4)]);

        let mut data = TokenRow::new();
        data.push(ColumnData::I32(Some(1)));

        let row = Row {
            columns,
            data,
            result_index: 0,
        };

        assert_eq!(Some(0), "r#foo".idx(&row));
        // No plain "foo" column exists, so the fallback finds nothing.
        assert_eq!(None, "foo".idx(&row));
    }

    #[test]
    fn row_accessors() {
        let row = make_row();

        assert_eq!(2, row.columns().len());
        assert_eq!(2, row.len());
        assert_eq!(0, row.result_index());

        let cells: Vec<_> = row.cells().collect();
        assert_eq!(2, cells.len());
        assert_eq!("foo", cells[0].0.name());

        let token_row = row.into_token_row();
        assert_eq!(2, token_row.len());
    }

    #[test]
    fn row_into_iterator_yields_column_data() {
        let row = make_row();
        let values: Vec<_> = row.into_iter().collect();
        assert_eq!(
            vec![ColumnData::I32(Some(1)), ColumnData::I32(Some(2))],
            values
        );
    }

    #[test]
    fn get_column_data_missing_cell_errors() {
        let columns = Arc::new(vec![
            Column::new("a".to_string(), ColumnType::Int4),
            Column::new("b".to_string(), ColumnType::Int4),
        ]);

        // Malformed row: metadata says 2 columns, but only 1 cell present.
        let mut data = TokenRow::new();
        data.push(ColumnData::I32(Some(1)));

        let row = Row {
            columns,
            data,
            result_index: 0,
        };

        let err = row.get_column_data(1usize).unwrap_err();
        assert!(format!("{}", err).contains("row has no data for column index"));
    }

    // A `Row` can be built via the public builder and its values
    // round-trip through the public accessors by index and by name, including
    // nulls and mixed types.
    #[test]
    fn builder_round_trips_through_public_accessors() {
        let row = Row::builder()
            .column("id", ColumnType::Int4, ColumnData::I32(Some(1)))
            .column(
                "name",
                ColumnType::NVarchar,
                ColumnData::String(Some("Alice".into())),
            )
            .column("flag", ColumnType::Bit, ColumnData::Bit(Some(true)))
            .column("age", ColumnType::Int4, ColumnData::I32(None))
            .build();

        // Shape.
        assert_eq!(4, row.len());
        assert_eq!(4, row.columns().len());
        assert_eq!(0, row.result_index());
        assert_eq!("id", row.columns()[0].name());
        assert_eq!(ColumnType::NVarchar, row.columns()[1].column_type());

        // By index.
        assert_eq!(Some(1i32), row.get::<i32, _>(0));
        assert_eq!(Some("Alice"), row.get::<&str, _>(1));
        assert_eq!(Some(true), row.get::<bool, _>(2));

        // By name.
        assert_eq!(Some(1i32), row.get::<i32, _>("id"));
        assert_eq!(Some("Alice"), row.get::<&str, _>("name"));
        assert_eq!(Some(true), row.get::<bool, _>("flag"));

        // Nulls round-trip as `None` for both index and name.
        assert_eq!(None, row.get::<i32, _>(3));
        assert_eq!(None, row.get::<i32, _>("age"));

        // try_get mirrors get and errors on an unknown column.
        assert_eq!(Some(1i32), row.try_get::<i32, _>("id").unwrap());
        assert!(row.try_get::<i32, _>("nope").is_err());
        assert!(row.try_get::<i32, _>(9usize).is_err());
    }

    #[test]
    fn builder_result_index_and_empty_row() {
        let row = Row::builder().result_index(7).build();
        assert_eq!(7, row.result_index());
        assert_eq!(0, row.len());
        assert!(row.columns().is_empty());
    }

    #[test]
    fn builder_empty_row_has_no_cells_or_columns() {
        let row = Row::builder().build();
        assert_eq!(0, row.len());
        assert_eq!(0, row.result_index());
        assert!(row.columns().is_empty());
        assert_eq!(0, row.cells().count());
        // Any lookup on an empty row is a miss.
        assert_eq!(None, 0usize.idx(&row));
        assert_eq!(None, "anything".idx(&row));
        assert!(row.try_get::<i32, _>(0usize).is_err());
        assert_eq!(0, row.into_iter().count());
    }

    #[test]
    fn builder_single_column() {
        let row = Row::builder()
            .column("only", ColumnType::Int4, ColumnData::I32(Some(99)))
            .build();

        assert_eq!(1, row.len());
        assert_eq!(1, row.columns().len());
        assert_eq!("only", row.columns()[0].name());
        assert_eq!(Some(99i32), row.get::<i32, _>(0));
        assert_eq!(Some(99i32), row.get::<i32, _>("only"));
    }

    #[test]
    fn builder_many_columns_by_index_and_name() {
        let mut builder = Row::builder();
        for i in 0..64i32 {
            builder = builder.column(format!("c{i}"), ColumnType::Int4, ColumnData::I32(Some(i)));
        }
        let row = builder.build();

        assert_eq!(64, row.len());
        assert_eq!(64, row.columns().len());
        for i in 0..64usize {
            assert_eq!(Some(i as i32), row.get::<i32, _>(i));
            assert_eq!(Some(i as i32), row.get::<i32, _>(format!("c{i}").as_str()));
        }
    }

    #[test]
    fn builder_int_variants_round_trip() {
        let row = Row::builder()
            .column("u8", ColumnType::Int1, ColumnData::U8(Some(200)))
            .column("i16", ColumnType::Int2, ColumnData::I16(Some(-30000)))
            .column("i32", ColumnType::Int4, ColumnData::I32(Some(123456)))
            .column(
                "i64",
                ColumnType::Int8,
                ColumnData::I64(Some(9_000_000_000)),
            )
            .build();

        assert_eq!(Some(200u8), row.get::<u8, _>("u8"));
        assert_eq!(Some(200u8), row.get::<u8, _>(0));
        assert_eq!(Some(-30000i16), row.get::<i16, _>("i16"));
        assert_eq!(Some(123456i32), row.get::<i32, _>("i32"));
        assert_eq!(Some(9_000_000_000i64), row.get::<i64, _>("i64"));
    }

    #[test]
    fn builder_int_nulls_round_trip_as_none() {
        let row = Row::builder()
            .column("u8", ColumnType::Int1, ColumnData::U8(None))
            .column("i16", ColumnType::Int2, ColumnData::I16(None))
            .column("i32", ColumnType::Int4, ColumnData::I32(None))
            .column("i64", ColumnType::Int8, ColumnData::I64(None))
            .build();

        assert_eq!(None, row.get::<u8, _>("u8"));
        assert_eq!(None, row.get::<i16, _>("i16"));
        assert_eq!(None, row.get::<i32, _>("i32"));
        assert_eq!(None, row.get::<i64, _>("i64"));
    }

    #[test]
    fn builder_float_variants_round_trip() {
        let row = Row::builder()
            .column("f32", ColumnType::Float4, ColumnData::F32(Some(1.5)))
            .column("f64", ColumnType::Float8, ColumnData::F64(Some(2.25)))
            .column("f32_null", ColumnType::Float4, ColumnData::F32(None))
            .column("f64_null", ColumnType::Float8, ColumnData::F64(None))
            .build();

        assert_eq!(Some(1.5f32), row.get::<f32, _>("f32"));
        assert_eq!(Some(2.25f64), row.get::<f64, _>("f64"));
        assert_eq!(None, row.get::<f32, _>("f32_null"));
        assert_eq!(None, row.get::<f64, _>("f64_null"));
    }

    #[test]
    fn builder_bool_round_trip() {
        let row = Row::builder()
            .column("t", ColumnType::Bit, ColumnData::Bit(Some(true)))
            .column("f", ColumnType::Bit, ColumnData::Bit(Some(false)))
            .column("n", ColumnType::Bitn, ColumnData::Bit(None))
            .build();

        assert_eq!(Some(true), row.get::<bool, _>("t"));
        assert_eq!(Some(false), row.get::<bool, _>("f"));
        assert_eq!(Some(true), row.get::<bool, _>(0));
        assert_eq!(None, row.get::<bool, _>("n"));
    }

    #[test]
    fn builder_string_owned_and_borrowed() {
        let row = Row::builder()
            .column(
                "owned",
                ColumnType::NVarchar,
                ColumnData::String(Some(Cow::Owned("owned".to_string()))),
            )
            .column(
                "borrowed",
                ColumnType::NVarchar,
                ColumnData::String(Some(Cow::Borrowed("borrowed"))),
            )
            .column("null", ColumnType::NVarchar, ColumnData::String(None))
            .build();

        assert_eq!(Some("owned"), row.get::<&str, _>("owned"));
        assert_eq!(Some("borrowed"), row.get::<&str, _>(1));
        // Owned `String` conversion goes through the by-value accessor.
        use crate::FromSqlOwned;
        let owned_cell = row.get_column_data("owned").unwrap().clone();
        assert_eq!(
            Some("owned".to_string()),
            String::from_sql_owned(owned_cell).unwrap()
        );
        assert_eq!(None, row.get::<&str, _>("null"));
    }

    #[test]
    fn builder_binary_round_trip() {
        let payload = vec![0u8, 1, 2, 3, 255];
        let row = Row::builder()
            .column(
                "bin",
                ColumnType::BigVarBin,
                ColumnData::Binary(Some(Cow::Owned(payload.clone()))),
            )
            .column("null", ColumnType::BigVarBin, ColumnData::Binary(None))
            .build();

        assert_eq!(Some(payload.as_slice()), row.get::<&[u8], _>("bin"));
        assert_eq!(Some(payload.as_slice()), row.get::<&[u8], _>(0));
        assert_eq!(None, row.get::<&[u8], _>("null"));
    }

    #[test]
    fn builder_guid_round_trip() {
        let uuid = crate::Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
        let row = Row::builder()
            .column("id", ColumnType::Guid, ColumnData::Guid(Some(uuid)))
            .column("null", ColumnType::Guid, ColumnData::Guid(None))
            .build();

        assert_eq!(Some(uuid), row.get::<crate::Uuid, _>("id"));
        assert_eq!(Some(uuid), row.get::<crate::Uuid, _>(0));
        assert_eq!(None, row.get::<crate::Uuid, _>("null"));
    }

    #[test]
    fn builder_numeric_round_trip() {
        let numeric = crate::tds::Numeric::new_with_scale(1234, 2);
        let row = Row::builder()
            .column(
                "n",
                ColumnType::Numericn,
                ColumnData::Numeric(Some(numeric)),
            )
            .column("null", ColumnType::Numericn, ColumnData::Numeric(None))
            .build();

        assert_eq!(Some(numeric), row.get::<crate::tds::Numeric, _>("n"));
        assert_eq!(Some(numeric), row.get::<crate::tds::Numeric, _>(0));
        assert_eq!(None, row.get::<crate::tds::Numeric, _>("null"));
    }

    #[test]
    fn builder_datetime_variants_round_trip_raw_cells() {
        // DateTime/SmallDateTime have no infallible Rust accessor without a
        // date feature, so assert the raw `ColumnData` is preserved verbatim.
        let dt = crate::time::DateTime::new(200, 3000);
        let sdt = crate::time::SmallDateTime::new(100, 200);

        let row = Row::builder()
            .column("dt", ColumnType::Datetime, ColumnData::DateTime(Some(dt)))
            .column(
                "sdt",
                ColumnType::Datetime4,
                ColumnData::SmallDateTime(Some(sdt)),
            )
            .column("dt_null", ColumnType::Datetimen, ColumnData::DateTime(None))
            .build();

        let cells: Vec<_> = row.into_iter().collect();
        assert_eq!(ColumnData::DateTime(Some(dt)), cells[0]);
        assert_eq!(ColumnData::SmallDateTime(Some(sdt)), cells[1]);
        assert_eq!(ColumnData::DateTime(None), cells[2]);
    }

    #[cfg(feature = "tds73")]
    #[test]
    fn builder_tds73_date_variants_round_trip_raw_cells() {
        let date = crate::time::Date::new(730119);
        let time = crate::time::Time::new(1234, 5);
        let dt2 = crate::time::DateTime2::new(date, time);
        let dto = crate::time::DateTimeOffset::new(dt2, 60);

        let row = Row::builder()
            .column("date", ColumnType::Daten, ColumnData::Date(Some(date)))
            .column("time", ColumnType::Timen, ColumnData::Time(Some(time)))
            .column(
                "dt2",
                ColumnType::Datetime2,
                ColumnData::DateTime2(Some(dt2)),
            )
            .column(
                "dto",
                ColumnType::DatetimeOffsetn,
                ColumnData::DateTimeOffset(Some(dto)),
            )
            .column("date_null", ColumnType::Daten, ColumnData::Date(None))
            .build();

        let cells: Vec<_> = row.cells().map(|(_, d)| d.clone()).collect();
        assert_eq!(ColumnData::Date(Some(date)), cells[0]);
        assert_eq!(ColumnData::Time(Some(time)), cells[1]);
        assert_eq!(ColumnData::DateTime2(Some(dt2)), cells[2]);
        assert_eq!(ColumnData::DateTimeOffset(Some(dto)), cells[3]);
        assert_eq!(ColumnData::Date(None), cells[4]);
    }

    #[test]
    fn builder_mixed_types_and_cells_iteration() {
        let row = Row::builder()
            .column("i", ColumnType::Int4, ColumnData::I32(Some(7)))
            .column(
                "s",
                ColumnType::NVarchar,
                ColumnData::String(Some(Cow::Borrowed("mix"))),
            )
            .column("b", ColumnType::Bit, ColumnData::Bit(Some(false)))
            .build();

        let cells: Vec<_> = row.cells().collect();
        assert_eq!(3, cells.len());
        assert_eq!("i", cells[0].0.name());
        assert_eq!(ColumnType::NVarchar, cells[1].0.column_type());
        assert_eq!(&ColumnData::Bit(Some(false)), cells[2].1);
    }

    #[test]
    fn builder_column_metadata_preserved() {
        let row = Row::builder()
            .column("a", ColumnType::Int8, ColumnData::I64(Some(1)))
            .column("b", ColumnType::NVarchar, ColumnData::String(None))
            .column("c", ColumnType::Bit, ColumnData::Bit(Some(true)))
            .build();

        assert_eq!("a", row.columns()[0].name());
        assert_eq!(ColumnType::Int8, row.columns()[0].column_type());
        assert_eq!("b", row.columns()[1].name());
        assert_eq!(ColumnType::NVarchar, row.columns()[1].column_type());
        assert_eq!("c", row.columns()[2].name());
        assert_eq!(ColumnType::Bit, row.columns()[2].column_type());
    }

    #[test]
    fn builder_duplicate_column_names_resolve_to_first_by_name() {
        let row = Row::builder()
            .column("dup", ColumnType::Int4, ColumnData::I32(Some(10)))
            .column("dup", ColumnType::Int4, ColumnData::I32(Some(20)))
            .build();

        // By-name resolves to the first matching column...
        assert_eq!(Some(0), "dup".idx(&row));
        assert_eq!(Some(10i32), row.get::<i32, _>("dup"));
        // ...while both remain independently addressable by index.
        assert_eq!(Some(10i32), row.get::<i32, _>(0));
        assert_eq!(Some(20i32), row.get::<i32, _>(1));
        assert_eq!(2, row.len());
    }

    #[test]
    fn builder_unknown_name_and_out_of_range_index() {
        let row = Row::builder()
            .column("known", ColumnType::Int4, ColumnData::I32(Some(1)))
            .build();

        assert_eq!(None, "missing".idx(&row));
        assert_eq!(None, 1usize.idx(&row));

        let by_name: crate::Result<Option<i32>> = row.try_get("missing");
        assert!(by_name.is_err());
        assert!(format!("{}", by_name.unwrap_err()).contains("Could not find column"));

        let by_index: crate::Result<Option<i32>> = row.try_get(5usize);
        assert!(by_index.is_err());
    }

    #[test]
    fn builder_wrong_type_conversion_errors() {
        let row = Row::builder()
            .column(
                "s",
                ColumnType::NVarchar,
                ColumnData::String(Some("x".into())),
            )
            .build();

        // Requesting an incompatible Rust type surfaces a conversion error
        // rather than panicking through `try_get`.
        let wrong: crate::Result<Option<i32>> = row.try_get("s");
        assert!(wrong.is_err());
        assert!(format!("{}", wrong.unwrap_err()).contains("cannot interpret"));
    }

    #[test]
    fn builder_by_index_and_by_name_agree() {
        let row = Row::builder()
            .column("x", ColumnType::Int4, ColumnData::I32(Some(11)))
            .column("y", ColumnType::Int4, ColumnData::I32(Some(22)))
            .build();

        assert_eq!(row.get::<i32, _>(0), row.get::<i32, _>("x"));
        assert_eq!(row.get::<i32, _>(1), row.get::<i32, _>("y"));
    }

    #[test]
    fn builder_result_index_variations() {
        for idx in [0usize, 1, 5, 42, usize::MAX] {
            let row = Row::builder()
                .result_index(idx)
                .column("c", ColumnType::Int4, ColumnData::I32(Some(0)))
                .build();
            assert_eq!(idx, row.result_index());
        }
    }

    #[test]
    fn builder_raw_identifier_column_names() {
        // A column named `type` is reachable via both `type` and `r#type`.
        let row = Row::builder()
            .column("foo", ColumnType::Int4, ColumnData::I32(Some(1)))
            .column("type", ColumnType::Int4, ColumnData::I32(Some(2)))
            .build();

        assert_eq!(Some(1), "type".idx(&row));
        assert_eq!(Some(1), "r#type".idx(&row));
        assert_eq!(Some(0), "r#foo".idx(&row));
        assert_eq!(None, "r#missing".idx(&row));
        assert_eq!(Some(2i32), row.get::<i32, _>("r#type"));
    }

    #[test]
    fn builder_literal_raw_prefixed_column_wins_over_fallback() {
        let row = Row::builder()
            .column("type", ColumnType::Int4, ColumnData::I32(Some(1)))
            .column("r#type", ColumnType::Int4, ColumnData::I32(Some(2)))
            .build();

        // Exact match wins before the `r#` strip fallback.
        assert_eq!(Some(0), "type".idx(&row));
        assert_eq!(Some(1), "r#type".idx(&row));
        assert_eq!(Some(1i32), row.get::<i32, _>("type"));
        assert_eq!(Some(2i32), row.get::<i32, _>("r#type"));
    }

    #[test]
    fn builder_into_token_row_preserves_data() {
        let row = Row::builder()
            .column("a", ColumnType::Int4, ColumnData::I32(Some(1)))
            .column("b", ColumnType::Int4, ColumnData::I32(Some(2)))
            .build();

        let token_row = row.into_token_row();
        assert_eq!(2, token_row.len());
        assert_eq!(Some(&ColumnData::I32(Some(1))), token_row.get(0));
        assert_eq!(Some(&ColumnData::I32(Some(2))), token_row.get(1));
    }

    #[test]
    fn builder_result_index_overwrites_and_is_order_independent() {
        // Last write wins, and the setter is independent of column order:
        // calling it twice and interleaving it with `column` still yields the
        // final value with all columns intact.
        let row = Row::builder()
            .result_index(3)
            .column("a", ColumnType::Int4, ColumnData::I32(Some(1)))
            .result_index(9)
            .column("b", ColumnType::Int4, ColumnData::I32(Some(2)))
            .build();

        assert_eq!(9, row.result_index());
        assert_eq!(2, row.len());
        assert_eq!(Some(1i32), row.get::<i32, _>("a"));
        assert_eq!(Some(2i32), row.get::<i32, _>("b"));
    }

    #[test]
    fn builder_usize_max_index_lookup_is_a_miss() {
        let row = Row::builder()
            .column("only", ColumnType::Int4, ColumnData::I32(Some(1)))
            .build();

        // A wildly out-of-range index resolves to `None` rather than panicking.
        assert_eq!(None, usize::MAX.idx(&row));
        assert!(row.try_get::<i32, _>(usize::MAX).is_err());
    }

    #[test]
    fn builder_empty_column_name_and_raw_prefix_only_lookup() {
        // Pins the interaction between an empty column name and the `r#` fallback
        // in `<&str as QueryIdx>::idx`: `"r#"` strips to `""` and matches the
        // empty-named column when no exact `"r#"` column exists.
        let row = Row::builder()
            .column("", ColumnType::Int4, ColumnData::I32(Some(1)))
            .build();

        assert_eq!(Some(0), "".idx(&row));
        assert_eq!(Some(0), "r#".idx(&row));
        assert_eq!(Some(1i32), row.get::<i32, _>(""));
        assert_eq!(Some(1i32), row.get::<i32, _>("r#"));
        // An unrelated name is still a miss.
        assert_eq!(None, "other".idx(&row));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn builder_row_serde_round_trips() {
        // `RowBuilder` is the first way to construct a `Row` without a live
        // connection, so it is also the first thing that can exercise the
        // feature-gated serde impls on `Row`. Assert a full round-trip preserves
        // the columns, the cell data, and the result index.
        let row = Row::builder()
            .result_index(2)
            .column("id", ColumnType::Int4, ColumnData::I32(Some(42)))
            .column(
                "name",
                ColumnType::NVarchar,
                ColumnData::String(Some("Alice".into())),
            )
            .column("age", ColumnType::Int4, ColumnData::I32(None))
            .build();

        let json = serde_json::to_string(&row).unwrap();
        let back: Row = serde_json::from_str(&json).unwrap();

        assert_eq!(2, back.result_index());
        assert_eq!(3, back.len());
        assert_eq!("id", back.columns()[0].name());
        assert_eq!(ColumnType::NVarchar, back.columns()[1].column_type());
        assert_eq!(Some(42i32), back.get::<i32, _>("id"));
        assert_eq!(Some("Alice"), back.get::<&str, _>("name"));
        assert_eq!(None, back.get::<i32, _>("age"));
    }

    #[test]
    fn column_new_and_accessors() {
        let column = Column::new("id".to_string(), ColumnType::Int8);
        assert_eq!("id", column.name());
        assert_eq!(ColumnType::Int8, column.column_type());
    }

    #[test]
    fn column_type_from_fixed_len_type_info() {
        use crate::tds::codec::FixedLenType;

        let cases = [
            (FixedLenType::Int1, ColumnType::Int1),
            (FixedLenType::Bit, ColumnType::Bit),
            (FixedLenType::Int2, ColumnType::Int2),
            (FixedLenType::Int4, ColumnType::Int4),
            (FixedLenType::Datetime4, ColumnType::Datetime4),
            (FixedLenType::Float4, ColumnType::Float4),
            (FixedLenType::Money, ColumnType::Money),
            (FixedLenType::Datetime, ColumnType::Datetime),
            (FixedLenType::Float8, ColumnType::Float8),
            (FixedLenType::Money4, ColumnType::Money4),
            (FixedLenType::Int8, ColumnType::Int8),
            (FixedLenType::Null, ColumnType::Null),
        ];

        for (flt, expected) in cases {
            let ti = TypeInfo::FixedLen(flt);
            assert_eq!(ColumnType::from(&ti), expected);
        }
    }

    #[test]
    fn column_type_from_var_len_sized_type_info() {
        use crate::tds::codec::VarLenType;
        use crate::VarLenContext;

        let cases = [
            (VarLenType::Guid, 16, ColumnType::Guid),
            (VarLenType::Intn, 1, ColumnType::Int1),
            (VarLenType::Intn, 2, ColumnType::Int2),
            (VarLenType::Intn, 4, ColumnType::Int4),
            (VarLenType::Intn, 8, ColumnType::Int8),
            (VarLenType::Intn, 3, ColumnType::Intn),
            (VarLenType::Bitn, 1, ColumnType::Bitn),
            (VarLenType::Decimaln, 17, ColumnType::Decimaln),
            (VarLenType::Numericn, 17, ColumnType::Numericn),
            (VarLenType::Floatn, 4, ColumnType::Float4),
            (VarLenType::Floatn, 8, ColumnType::Float8),
            (VarLenType::Floatn, 2, ColumnType::Floatn),
            (VarLenType::Money, 8, ColumnType::Money),
            (VarLenType::Datetimen, 8, ColumnType::Datetimen),
            (VarLenType::BigVarBin, 8000, ColumnType::BigVarBin),
            (VarLenType::BigVarChar, 8000, ColumnType::BigVarChar),
            (VarLenType::BigBinary, 8000, ColumnType::BigBinary),
            (VarLenType::BigChar, 8000, ColumnType::BigChar),
            (VarLenType::NVarchar, 4000, ColumnType::NVarchar),
            (VarLenType::NChar, 4000, ColumnType::NChar),
            (VarLenType::Xml, 0, ColumnType::Xml),
            (VarLenType::Udt, 0, ColumnType::Udt),
            (VarLenType::Text, 0, ColumnType::Text),
            (VarLenType::Image, 0, ColumnType::Image),
            (VarLenType::NText, 0, ColumnType::NText),
            (VarLenType::SSVariant, 0, ColumnType::SSVariant),
        ];

        for (ty, len, expected) in cases {
            let ti = TypeInfo::VarLenSized(VarLenContext::new(ty, len, None));
            assert_eq!(ColumnType::from(&ti), expected, "{:?} len {}", ty, len);
        }
    }

    #[test]
    fn column_type_from_var_len_sized_precision_type_info() {
        use crate::tds::codec::VarLenType;

        let cases = [
            (VarLenType::Guid, ColumnType::Guid),
            (VarLenType::Intn, ColumnType::Intn),
            (VarLenType::Bitn, ColumnType::Bitn),
            (VarLenType::Decimaln, ColumnType::Decimaln),
            (VarLenType::Numericn, ColumnType::Numericn),
            (VarLenType::Floatn, ColumnType::Floatn),
            (VarLenType::Money, ColumnType::Money),
            (VarLenType::Datetimen, ColumnType::Datetimen),
            (VarLenType::BigVarBin, ColumnType::BigVarBin),
            (VarLenType::BigVarChar, ColumnType::BigVarChar),
            (VarLenType::BigBinary, ColumnType::BigBinary),
            (VarLenType::BigChar, ColumnType::BigChar),
            (VarLenType::NVarchar, ColumnType::NVarchar),
            (VarLenType::NChar, ColumnType::NChar),
            (VarLenType::Xml, ColumnType::Xml),
            (VarLenType::Udt, ColumnType::Udt),
            (VarLenType::Text, ColumnType::Text),
            (VarLenType::Image, ColumnType::Image),
            (VarLenType::NText, ColumnType::NText),
            (VarLenType::SSVariant, ColumnType::SSVariant),
        ];

        for (ty, expected) in cases {
            let ti = TypeInfo::VarLenSizedPrecision {
                ty,
                size: 38,
                precision: 38,
                scale: 2,
            };
            assert_eq!(ColumnType::from(&ti), expected, "{:?}", ty);
        }
    }

    #[test]
    fn column_type_from_xml_and_udt_type_info() {
        use crate::tds::codec::UdtInfo;
        use crate::tds::xml::XmlSchema;
        use std::sync::Arc as StdArc;

        let ti = TypeInfo::Xml {
            schema: None::<StdArc<XmlSchema>>,
            size: 0,
        };
        assert_eq!(ColumnType::from(&ti), ColumnType::Xml);

        let ti = TypeInfo::Udt(UdtInfo {
            max_byte_size: 0xffff,
            db_name: "db".to_string(),
            schema_name: "dbo".to_string(),
            type_name: "geometry".to_string(),
            assembly_qualified_name: "asm".to_string(),
        });
        assert_eq!(ColumnType::from(&ti), ColumnType::Udt);
    }

    #[cfg(feature = "tds73")]
    #[test]
    fn column_type_from_var_len_sized_tds73_type_info() {
        use crate::tds::codec::VarLenType;
        use crate::VarLenContext;

        let cases = [
            (VarLenType::Daten, ColumnType::Daten),
            (VarLenType::Timen, ColumnType::Timen),
            (VarLenType::Datetime2, ColumnType::Datetime2),
            (VarLenType::DatetimeOffsetn, ColumnType::DatetimeOffsetn),
        ];

        for (ty, expected) in cases {
            let ti = TypeInfo::VarLenSized(VarLenContext::new(ty, 8, None));
            assert_eq!(ColumnType::from(&ti), expected, "{:?}", ty);
        }
    }

    #[cfg(feature = "tds73")]
    #[test]
    fn column_type_from_var_len_sized_precision_tds73_type_info() {
        use crate::tds::codec::VarLenType;

        let cases = [
            (VarLenType::Daten, ColumnType::Daten),
            (VarLenType::Timen, ColumnType::Timen),
            (VarLenType::Datetime2, ColumnType::Datetime2),
            (VarLenType::DatetimeOffsetn, ColumnType::DatetimeOffsetn),
        ];

        for (ty, expected) in cases {
            let ti = TypeInfo::VarLenSizedPrecision {
                ty,
                size: 8,
                precision: 0,
                scale: 7,
            };
            assert_eq!(ColumnType::from(&ti), expected, "{:?}", ty);
        }
    }
}
