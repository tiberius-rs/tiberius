use crate::{
    tds::{codec::ColumnData, Numeric},
    xml::XmlData,
};
use std::borrow::Cow;
use uuid::Uuid;

/// A conversion trait to a TDS type.
///
/// A `ToSql` implementation for a Rust type is needed for using it as a
/// parameter in the [`Client#query`] or [`Client#execute`] methods. The
/// following Rust types are already implemented to match the given server
/// types:
///
/// |Rust type|Server type|
/// |--------|--------|
/// |`u8`|`tinyint`|
/// |`i16`|`smallint`|
/// |`i32`|`int`|
/// |`i64`|`bigint`|
/// |`f32`|`float(24)`|
/// |`f64`|`float(53)`|
/// |`bool`|`bit`|
/// |`String`/`&str` (< 4000 characters)|`nvarchar(4000)`|
/// |`String`/`&str`|`nvarchar(max)`|
/// |`Vec<u8>`/`&[u8]` (< 8000 bytes)|`varbinary(8000)`|
/// |`Vec<u8>`/`&[u8]`|`varbinary(max)`|
/// |[`Uuid`]|`uniqueidentifier`|
/// |[`Numeric`]|`numeric`/`decimal`|
/// |[`Decimal`] (with feature flag `rust_decimal`)|`numeric`/`decimal`|
/// |[`BigDecimal`] (with feature flag `bigdecimal`)|`numeric`/`decimal`|
/// |[`XmlData`]|`xml`|
/// |[`NaiveDate`] (with `chrono` feature, TDS 7.3 >)|`date`|
/// |[`NaiveTime`] (with `chrono` feature, TDS 7.3 >)|`time`|
/// |[`DateTime`] (with `chrono` feature, TDS 7.3 >)|`datetimeoffset`|
/// |[`NaiveDateTime`] (with `chrono` feature, TDS 7.3 >)|`datetime2`|
/// |[`NaiveDateTime`] (with `chrono` feature, TDS 7.2)|`datetime`|
///
/// It is possible to use some of the types to write into columns that are not
/// of the same type. For example on systems following the TDS 7.3 standard (SQL
/// Server 2008 and later), the chrono type `NaiveDateTime` can also be used to
/// write to `datetime`, `datetime2` and `smalldatetime` columns. All string
/// types can also be used with `ntext`, `text`, `varchar`, `nchar` and `char`
/// columns. All binary types can also be used with `binary` and `image`
/// columns.
///
/// See the [`time`] module for more information about the date and time structs.
///
/// [`Client#query`]: struct.Client.html#method.query
/// [`Client#execute`]: struct.Client.html#method.execute
/// [`time`]: time/index.html
/// [`Uuid`]: struct.Uuid.html
/// [`Numeric`]: numeric/struct.Numeric.html
/// [`Decimal`]: numeric/struct.Decimal.html
/// [`BigDecimal`]: numeric/struct.BigDecimal.html
/// [`XmlData`]: xml/struct.XmlData.html
/// [`NaiveDateTime`]: time/chrono/struct.NaiveDateTime.html
/// [`NaiveDate`]: time/chrono/struct.NaiveDate.html
/// [`NaiveTime`]: time/chrono/struct.NaiveTime.html
/// [`DateTime`]: time/chrono/struct.DateTime.html
pub trait ToSql: Send + Sync {
    /// Convert to a value understood by the SQL Server. Conversion
    /// by-reference.
    fn to_sql(&self) -> ColumnData<'_>;
}

/// A by-value conversion trait to a TDS type.
pub trait IntoSql<'a>: Send + Sync {
    /// Convert to a value understood by the SQL Server. Conversion by-value.
    fn into_sql(self) -> ColumnData<'a>;
}

impl<'a> IntoSql<'a> for &'a str {
    fn into_sql(self) -> ColumnData<'a> {
        ColumnData::String(Some(Cow::Borrowed(self)))
    }
}

impl<'a> IntoSql<'a> for Option<&'a str> {
    fn into_sql(self) -> ColumnData<'a> {
        ColumnData::String(self.map(Cow::Borrowed))
    }
}

impl<'a> IntoSql<'a> for &'a String {
    fn into_sql(self) -> ColumnData<'a> {
        ColumnData::String(Some(Cow::Borrowed(self)))
    }
}

impl<'a> IntoSql<'a> for Option<&'a String> {
    fn into_sql(self) -> ColumnData<'a> {
        ColumnData::String(self.map(Cow::from))
    }
}

impl<'a> IntoSql<'a> for &'a [u8] {
    fn into_sql(self) -> ColumnData<'a> {
        ColumnData::Binary(Some(Cow::Borrowed(self)))
    }
}

impl<'a> IntoSql<'a> for Option<&'a [u8]> {
    fn into_sql(self) -> ColumnData<'a> {
        ColumnData::Binary(self.map(Cow::Borrowed))
    }
}

impl<'a> IntoSql<'a> for &'a Vec<u8> {
    fn into_sql(self) -> ColumnData<'a> {
        ColumnData::Binary(Some(Cow::from(self)))
    }
}

impl<'a> IntoSql<'a> for Option<&'a Vec<u8>> {
    fn into_sql(self) -> ColumnData<'a> {
        ColumnData::Binary(self.map(Cow::from))
    }
}

impl<'a> IntoSql<'a> for Cow<'a, str> {
    fn into_sql(self) -> ColumnData<'a> {
        ColumnData::String(Some(self))
    }
}

impl<'a> IntoSql<'a> for Option<Cow<'a, str>> {
    fn into_sql(self) -> ColumnData<'a> {
        ColumnData::String(self)
    }
}

impl<'a> IntoSql<'a> for Cow<'a, [u8]> {
    fn into_sql(self) -> ColumnData<'a> {
        ColumnData::Binary(Some(self))
    }
}

impl<'a> IntoSql<'a> for Option<Cow<'a, [u8]>> {
    fn into_sql(self) -> ColumnData<'a> {
        ColumnData::Binary(self)
    }
}

impl<'a> IntoSql<'a> for &'a XmlData {
    fn into_sql(self) -> ColumnData<'a> {
        ColumnData::Xml(Some(Cow::Borrowed(self)))
    }
}

impl<'a> IntoSql<'a> for Option<&'a XmlData> {
    fn into_sql(self) -> ColumnData<'a> {
        ColumnData::Xml(self.map(Cow::Borrowed))
    }
}

impl<'a> IntoSql<'a> for &'a Uuid {
    fn into_sql(self) -> ColumnData<'a> {
        ColumnData::Guid(Some(*self))
    }
}

impl<'a> IntoSql<'a> for Option<&'a Uuid> {
    fn into_sql(self) -> ColumnData<'a> {
        ColumnData::Guid(self.copied())
    }
}

into_sql!(self_,
          String: (ColumnData::String, Cow::from(self_));
          Vec<u8>: (ColumnData::Binary, Cow::from(self_));
          Numeric: (ColumnData::Numeric, self_);
          XmlData: (ColumnData::Xml, Cow::Owned(self_));
          Uuid: (ColumnData::Guid, self_);
          bool: (ColumnData::Bit, self_);
          u8: (ColumnData::U8, self_);
          i16: (ColumnData::I16, self_);
          i32: (ColumnData::I32, self_);
          i64: (ColumnData::I64, self_);
          f32: (ColumnData::F32, self_);
          f64: (ColumnData::F64, self_);
);

to_sql!(self_,
        bool: (ColumnData::Bit, *self_);
        u8: (ColumnData::U8, *self_);
        i16: (ColumnData::I16, *self_);
        i32: (ColumnData::I32, *self_);
        i64: (ColumnData::I64, *self_);
        f32: (ColumnData::F32, *self_);
        f64: (ColumnData::F64, *self_);
        &str: (ColumnData::String, Cow::from(*self_));
        String: (ColumnData::String, Cow::from(self_));
        Cow<'_, str>: (ColumnData::String, self_.clone());
        &[u8]: (ColumnData::Binary, Cow::from(*self_));
        Cow<'_, [u8]>: (ColumnData::Binary, self_.clone());
        Vec<u8>: (ColumnData::Binary, Cow::from(self_));
        Numeric: (ColumnData::Numeric, *self_);
        XmlData: (ColumnData::Xml, Cow::Borrowed(self_));
        Uuid: (ColumnData::Guid, *self_);
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tds::Numeric;
    use crate::{IntoSql, ToSql};

    #[test]
    fn to_sql_scalars() {
        assert_eq!(true.to_sql(), ColumnData::Bit(Some(true)));
        assert_eq!(8u8.to_sql(), ColumnData::U8(Some(8)));
        assert_eq!(16i16.to_sql(), ColumnData::I16(Some(16)));
        assert_eq!(32i32.to_sql(), ColumnData::I32(Some(32)));
        assert_eq!(64i64.to_sql(), ColumnData::I64(Some(64)));
        assert_eq!(1.5f32.to_sql(), ColumnData::F32(Some(1.5)));
        assert_eq!(2.5f64.to_sql(), ColumnData::F64(Some(2.5)));
    }

    #[test]
    // The `&Some(..)`/`&None` borrows are intentional: they exercise the
    // `ToSql for &T` impls, not the by-value ones, so the borrow is not needless.
    #[allow(clippy::needless_borrow)]
    fn to_sql_option_some_and_none() {
        assert_eq!(Some(1i32).to_sql(), ColumnData::I32(Some(1)));
        assert_eq!(None::<i32>.to_sql(), ColumnData::I32(None));
        assert_eq!((&Some(1i32)).to_sql(), ColumnData::I32(Some(1)));
        assert_eq!((&None::<i32>).to_sql(), ColumnData::I32(None));
    }

    #[test]
    fn to_sql_strings_and_binary() {
        assert_eq!("abc".to_sql(), ColumnData::String(Some(Cow::from("abc"))));
        assert_eq!(
            String::from("abc").to_sql(),
            ColumnData::String(Some(Cow::from("abc")))
        );
        let v = vec![1u8, 2, 3];
        assert_eq!(
            v.to_sql(),
            ColumnData::Binary(Some(Cow::from(vec![1, 2, 3])))
        );
        assert_eq!(
            [1u8, 2, 3].as_slice().to_sql(),
            ColumnData::Binary(Some(Cow::from(vec![1, 2, 3])))
        );
    }

    #[test]
    fn to_sql_numeric_and_uuid() {
        let n = Numeric::new_with_scale(5, 1);
        assert_eq!(n.to_sql(), ColumnData::Numeric(Some(n)));

        let uuid = Uuid::nil();
        assert_eq!(uuid.to_sql(), ColumnData::Guid(Some(uuid)));
    }

    #[test]
    fn into_sql_borrowed_and_owned() {
        assert_eq!(
            "abc".into_sql(),
            ColumnData::String(Some(Cow::Borrowed("abc")))
        );
        assert_eq!(
            Some("abc").into_sql(),
            ColumnData::String(Some(Cow::Borrowed("abc")))
        );
        assert_eq!(None::<&str>.into_sql(), ColumnData::String(None));

        let bytes = vec![9u8, 8, 7];
        assert_eq!(
            bytes.as_slice().into_sql(),
            ColumnData::Binary(Some(Cow::Borrowed(bytes.as_slice())))
        );
        assert_eq!(
            (&bytes).into_sql(),
            ColumnData::Binary(Some(Cow::from(&bytes)))
        );

        let uuid = Uuid::nil();
        assert_eq!((&uuid).into_sql(), ColumnData::Guid(Some(uuid)));
        assert_eq!(Some(&uuid).into_sql(), ColumnData::Guid(Some(uuid)));
        assert_eq!(None::<&Uuid>.into_sql(), ColumnData::Guid(None));
    }

    #[test]
    fn into_sql_scalars() {
        assert_eq!(true.into_sql(), ColumnData::Bit(Some(true)));
        assert_eq!(5i32.into_sql(), ColumnData::I32(Some(5)));
        assert_eq!(None::<i32>.into_sql(), ColumnData::I32(None));
        assert_eq!(
            String::from("x").into_sql(),
            ColumnData::String(Some(Cow::from("x")))
        );
    }

    #[test]
    fn into_sql_owned_string_and_ref() {
        let owned = String::from("abc");
        assert_eq!(
            (&owned).into_sql(),
            ColumnData::String(Some(Cow::from("abc")))
        );
        assert_eq!(
            Some(&owned).into_sql(),
            ColumnData::String(Some(Cow::from("abc")))
        );
        assert_eq!(None::<&String>.into_sql(), ColumnData::String(None));
    }

    #[test]
    fn into_sql_binary_option_variants() {
        assert_eq!(None::<&[u8]>.into_sql(), ColumnData::Binary(None));

        let bytes = vec![1u8, 2, 3];
        assert_eq!(
            Some(bytes.as_slice()).into_sql(),
            ColumnData::Binary(Some(Cow::from(bytes.as_slice())))
        );
        assert_eq!(None::<&Vec<u8>>.into_sql(), ColumnData::Binary(None));
        assert_eq!(
            bytes.into_sql(),
            ColumnData::Binary(Some(Cow::from(vec![1, 2, 3])))
        );
    }

    #[test]
    fn into_sql_cow_variants() {
        let cow_str: Cow<'_, str> = Cow::Borrowed("hi");
        assert_eq!(
            cow_str.into_sql(),
            ColumnData::String(Some(Cow::from("hi")))
        );
        assert_eq!(
            Some(Cow::Borrowed("hi")).into_sql(),
            ColumnData::String(Some(Cow::from("hi")))
        );
        assert_eq!(None::<Cow<'_, str>>.into_sql(), ColumnData::String(None));

        let cow_bin: Cow<'_, [u8]> = Cow::Borrowed(&[1u8, 2][..]);
        assert_eq!(
            cow_bin.into_sql(),
            ColumnData::Binary(Some(Cow::from(vec![1u8, 2])))
        );
        assert_eq!(
            Some(Cow::<[u8]>::Borrowed(&[1u8, 2][..])).into_sql(),
            ColumnData::Binary(Some(Cow::from(vec![1u8, 2])))
        );
        assert_eq!(None::<Cow<'_, [u8]>>.into_sql(), ColumnData::Binary(None));
    }

    #[test]
    fn into_sql_xml_and_numeric() {
        let xml = XmlData::new("<a/>".to_string());
        assert_eq!(
            (&xml).into_sql(),
            ColumnData::Xml(Some(Cow::Borrowed(&xml)))
        );
        assert_eq!(
            Some(&xml).into_sql(),
            ColumnData::Xml(Some(Cow::Borrowed(&xml)))
        );
        assert_eq!(None::<&XmlData>.into_sql(), ColumnData::Xml(None));

        let xml_owned = XmlData::new("<b/>".to_string());
        assert_eq!(
            xml_owned.clone().into_sql(),
            ColumnData::Xml(Some(Cow::Owned(xml_owned)))
        );

        let n = Numeric::new_with_scale(42, 0);
        assert_eq!(n.into_sql(), ColumnData::Numeric(Some(n)));
    }

    #[test]
    // The `&value` borrows are intentional: they exercise the `ToSql for &T`
    // impls for the base scalar types, so the borrow is not needless.
    #[allow(clippy::needless_borrow)]
    fn to_sql_by_reference_scalars() {
        // The macro-generated impls also cover `&T` for the base scalar types.
        assert_eq!((&true).to_sql(), ColumnData::Bit(Some(true)));
        assert_eq!((&8u8).to_sql(), ColumnData::U8(Some(8)));
        assert_eq!((&16i16).to_sql(), ColumnData::I16(Some(16)));
        assert_eq!((&64i64).to_sql(), ColumnData::I64(Some(64)));
        assert_eq!((&1.5f32).to_sql(), ColumnData::F32(Some(1.5)));
        assert_eq!((&2.5f64).to_sql(), ColumnData::F64(Some(2.5)));
    }

    #[test]
    fn to_sql_cow_variants() {
        let cow_str: Cow<'_, str> = Cow::Borrowed("hi");
        assert_eq!(cow_str.to_sql(), ColumnData::String(Some(Cow::from("hi"))));

        let cow_bin: Cow<'_, [u8]> = Cow::Borrowed(&[1u8, 2][..]);
        assert_eq!(
            cow_bin.to_sql(),
            ColumnData::Binary(Some(Cow::from(vec![1u8, 2])))
        );
    }

    #[test]
    fn to_sql_xml() {
        let xml = XmlData::new("<a/>".to_string());
        assert_eq!(xml.to_sql(), ColumnData::Xml(Some(Cow::Borrowed(&xml))));
    }
}
