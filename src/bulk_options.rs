//! Options controlling the behaviour of a bulk-insert (`INSERT BULK`)
//! operation, mirroring the knobs exposed by `SqlBulkCopyOptions` in
//! ADO.NET's `SqlBulkCopy`.

use enumflags2::{bitflags, BitFlags};

/// A single bulk-copy option. Combine several with the `|` operator to build a
/// [`SqlBulkCopyOptions`] set, e.g.
/// `SqlBulkCopyOption::KeepIdentity | SqlBulkCopyOption::TableLock`.
///
/// See the MS docs for `SqlBulkCopyOptions`:
/// <https://learn.microsoft.com/en-us/dotnet/api/system.data.sqlclient.sqlbulkcopyoptions>
#[bitflags]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SqlBulkCopyOption {
    /// Preserve source identity values. When not specified, identity values are
    /// assigned by the destination. Implemented by keeping the identity column
    /// in the bulk column list (the `INSERT BULK` `WITH (...)` grammar has no
    /// `KEEP_IDENTITY` keyword), matching ADO.NET's `SqlBulkCopy`.
    KeepIdentity = 1 << 0,
    /// Check constraints while data is being inserted. By default, constraints
    /// are not checked. Emits `CHECK_CONSTRAINTS`.
    CheckConstraints = 1 << 1,
    /// Obtain a bulk update lock for the duration of the bulk-copy operation.
    /// When not specified, row locks are used. Emits `TABLOCK`.
    TableLock = 1 << 2,
    /// Preserve null values in the destination table regardless of the settings
    /// for default values. When not specified, null values are replaced by
    /// default values where applicable. Emits `KEEP_NULLS`.
    KeepNulls = 1 << 3,
    /// Cause the server to fire the insert triggers for the rows being inserted
    /// into the database. Emits `FIRE_TRIGGERS`.
    FireTriggers = 1 << 4,
}

/// A set of [`SqlBulkCopyOption`] flags controlling an `INSERT BULK`.
///
/// Build one by combining flags with `|`, or use [`SqlBulkCopyOptions::empty`]
/// (also the [`Default`]) for no options:
///
/// ```
/// # use tiberius::{SqlBulkCopyOption, SqlBulkCopyOptions};
/// let opts: SqlBulkCopyOptions =
///     SqlBulkCopyOption::KeepIdentity | SqlBulkCopyOption::TableLock;
/// assert!(opts.contains(SqlBulkCopyOption::KeepIdentity));
/// assert!(SqlBulkCopyOptions::empty().is_empty());
/// ```
pub type SqlBulkCopyOptions = BitFlags<SqlBulkCopyOption>;

/// The sort order of a column, used as a bulk-insert `ORDER (...)` hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SortOrder {
    /// Ascending order (`ASC`).
    Ascending,
    /// Descending order (`DESC`).
    Descending,
}

/// An order hint for a bulk insert: the column name and the [`SortOrder`] the
/// incoming rows are already sorted by. Passed as a slice, e.g.
/// `&[("id", SortOrder::Ascending)]`, these become the `ORDER (...)` clause of
/// the `INSERT BULK` statement.
pub type ColumnOrderHint<'a> = (&'a str, SortOrder);
