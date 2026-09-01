use crate::{tds::Numeric, xml::XmlData, ColumnData};
use uuid::Uuid;

/// A conversion trait from a TDS type by-reference.
///
/// A `FromSql` implementation for a Rust type is needed for using it as a
/// return parameter from [`Row#get`] or [`Row#try_get`] methods. The following
/// Rust types are already implemented to match the given server types:
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
/// |`String`/`&str`|`nvarchar`/`varchar`/`nchar`/`char`/`ntext`/`text`|
/// |`Vec<u8>`/`&[u8]`|`binary`/`varbinary`/`image`|
/// |[`Uuid`]|`uniqueidentifier`|
/// |[`Numeric`]|`numeric`/`decimal`|
/// |[`Decimal`] (with feature flag `rust_decimal`)|`numeric`/`decimal`|
/// |[`XmlData`]|`xml`|
/// |[`NaiveDateTime`] (with feature flag `chrono`)|`datetime`/`datetime2`/`smalldatetime`|
/// |[`NaiveDate`] (with feature flag `chrono`)|`date`|
/// |[`NaiveTime`] (with feature flag `chrono`)|`time`|
/// |[`DateTime`] (with feature flag `chrono`)|`datetimeoffset`|
///
/// See the [`time`] module for more information about the date and time structs.
///
/// [`Row#get`]: struct.Row.html#method.get
/// [`Row#try_get`]: struct.Row.html#method.try_get
/// [`time`]: time/index.html
/// [`Uuid`]: struct.Uuid.html
/// [`Numeric`]: numeric/struct.Numeric.html
/// [`Decimal`]: numeric/struct.Decimal.html
/// [`XmlData`]: xml/struct.XmlData.html
/// [`NaiveDateTime`]: time/chrono/struct.NaiveDateTime.html
/// [`NaiveDate`]: time/chrono/struct.NaiveDate.html
/// [`NaiveTime`]: time/chrono/struct.NaiveTime.html
/// [`DateTime`]: time/chrono/struct.DateTime.html
pub trait FromSql<'a>
where
    Self: Sized + 'a,
{
    /// Returns the value, `None` being a null value, copying the value.
    fn from_sql(value: &'a ColumnData<'static>) -> crate::Result<Option<Self>>;
}

/// A conversion trait from a TDS type by-value.
pub trait FromSqlOwned
where
    Self: Sized,
{
    /// Returns the value, `None` being a null value, taking the ownership.
    fn from_sql_owned(value: ColumnData<'static>) -> crate::Result<Option<Self>>;
}

from_sql!(bool: ColumnData::Bit(val) => (*val, val));
from_sql!(u8: ColumnData::U8(val) => (*val, val), ColumnData::I32(None) => (None, None));
from_sql!(i16: ColumnData::I16(val) => (*val, val), ColumnData::U8(None) => (None, None), ColumnData::I32(None) => (None, None));
from_sql!(i32: ColumnData::I32(val) => (*val, val), ColumnData::I16(val) => (val.map(i32::from), val.map(i32::from)), ColumnData::U8(None) => (None, None));
from_sql!(i64: ColumnData::I64(val) => (*val, val), ColumnData::U8(None) => (None, None), ColumnData::I32(None) => (None, None));
from_sql!(f32: ColumnData::F32(val) => (*val, val));
from_sql!(f64: ColumnData::F64(val) => (*val, val));
from_sql!(Uuid: ColumnData::Guid(val) => (*val, val));
from_sql!(Numeric: ColumnData::Numeric(n) => (*n, n));

impl FromSqlOwned for XmlData {
    fn from_sql_owned(value: ColumnData<'static>) -> crate::Result<Option<Self>> {
        match value {
            ColumnData::Xml(data) => Ok(data.map(|data| data.into_owned())),
            v => Err(crate::Error::Conversion(
                format!("cannot interpret {:?} as a String value", v).into(),
            )),
        }
    }
}

impl<'a> FromSql<'a> for &'a XmlData {
    fn from_sql(value: &'a ColumnData<'static>) -> crate::Result<Option<Self>> {
        match value {
            ColumnData::Xml(data) => Ok(data.as_ref().map(|s| s.as_ref())),
            v => Err(crate::Error::Conversion(
                format!("cannot interpret {:?} as a String value", v).into(),
            )),
        }
    }
}

impl FromSqlOwned for String {
    fn from_sql_owned(value: ColumnData<'static>) -> crate::Result<Option<Self>> {
        match value {
            ColumnData::String(s) => Ok(s.map(|s| s.into_owned())),
            v => Err(crate::Error::Conversion(
                format!("cannot interpret {:?} as a String value", v).into(),
            )),
        }
    }
}

impl<'a> FromSql<'a> for &'a str {
    fn from_sql(value: &'a ColumnData<'static>) -> crate::Result<Option<Self>> {
        match value {
            ColumnData::String(s) => Ok(s.as_ref().map(|s| s.as_ref())),
            v => Err(crate::Error::Conversion(
                format!("cannot interpret {:?} as a String value", v).into(),
            )),
        }
    }
}

impl FromSqlOwned for Vec<u8> {
    fn from_sql_owned(value: ColumnData<'static>) -> crate::Result<Option<Self>> {
        match value {
            ColumnData::Binary(b) => Ok(b.map(|s| s.into_owned())),
            v => Err(crate::Error::Conversion(
                format!("cannot interpret {:?} as a String value", v).into(),
            )),
        }
    }
}

impl<'a> FromSql<'a> for &'a [u8] {
    fn from_sql(value: &'a ColumnData<'static>) -> crate::Result<Option<Self>> {
        match value {
            ColumnData::Binary(b) => Ok(b.as_ref().map(|s| s.as_ref())),
            v => Err(crate::Error::Conversion(
                format!("cannot interpret {:?} as a &[u8] value", v).into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn i16_column_converts_to_i32() {
        let data = ColumnData::I16(Some(8));
        assert_eq!(Some(8i32), i32::from_sql(&data).unwrap());
        assert_eq!(Some(8i32), i32::from_sql_owned(data).unwrap());
    }

    #[test]
    fn null_i16_column_converts_to_i32() {
        let data = ColumnData::I16(None);
        assert_eq!(None, i32::from_sql(&data).unwrap());
        assert_eq!(None, i32::from_sql_owned(ColumnData::I16(None)).unwrap());
    }

    #[test]
    fn bool_from_bit() {
        let data = ColumnData::Bit(Some(true));
        assert_eq!(Some(true), bool::from_sql(&data).unwrap());
        assert_eq!(Some(true), bool::from_sql_owned(data).unwrap());
    }

    #[test]
    fn u8_from_u8_and_null_i32() {
        let data = ColumnData::U8(Some(5));
        assert_eq!(Some(5u8), u8::from_sql(&data).unwrap());
        assert_eq!(Some(5u8), u8::from_sql_owned(data).unwrap());

        let null = ColumnData::I32(None);
        assert_eq!(None, u8::from_sql(&null).unwrap());
        assert_eq!(None, u8::from_sql_owned(null).unwrap());
    }

    #[test]
    fn i16_from_wrong_variant_errors() {
        let data = ColumnData::F64(Some(1.0));
        let err = i16::from_sql(&data).unwrap_err();
        assert!(format!("{}", err).contains("cannot interpret"));
    }

    #[test]
    fn i64_from_i64_and_null() {
        let data = ColumnData::I64(Some(42));
        assert_eq!(Some(42i64), i64::from_sql(&data).unwrap());
        assert_eq!(Some(42i64), i64::from_sql_owned(data).unwrap());

        let null = ColumnData::U8(None);
        assert_eq!(None, i64::from_sql_owned(null).unwrap());
    }

    #[test]
    fn f32_and_f64_from_sql() {
        let f32_data = ColumnData::F32(Some(1.5));
        assert_eq!(Some(1.5f32), f32::from_sql(&f32_data).unwrap());

        let f64_data = ColumnData::F64(Some(2.5));
        assert_eq!(Some(2.5f64), f64::from_sql(&f64_data).unwrap());
    }

    #[test]
    fn uuid_from_guid() {
        let uuid = Uuid::new_v4();
        let data = ColumnData::Guid(Some(uuid));
        assert_eq!(Some(uuid), Uuid::from_sql(&data).unwrap());
        assert_eq!(Some(uuid), Uuid::from_sql_owned(data).unwrap());
    }

    #[test]
    fn numeric_from_numeric() {
        let numeric = crate::tds::Numeric::new_with_scale(1234, 2);
        let data = ColumnData::Numeric(Some(numeric));
        assert_eq!(Some(numeric), Numeric::from_sql(&data).unwrap());
        assert_eq!(Some(numeric), Numeric::from_sql_owned(data).unwrap());
    }

    #[test]
    fn xml_data_owned_and_borrowed() {
        let xml = XmlData::new("<a/>".to_string());
        let data = ColumnData::Xml(Some(std::borrow::Cow::Owned(xml.clone())));

        let borrowed = <&XmlData as FromSql>::from_sql(&data).unwrap().unwrap();
        assert_eq!(borrowed.to_string(), xml.to_string());

        let owned = XmlData::from_sql_owned(data).unwrap().unwrap();
        assert_eq!(owned.to_string(), xml.to_string());
    }

    #[test]
    fn xml_data_wrong_variant_errors() {
        let data = ColumnData::I32(Some(1));
        let err = XmlData::from_sql_owned(data).unwrap_err();
        assert!(format!("{}", err).contains("cannot interpret"));

        let data = ColumnData::I32(Some(1));
        let err = <&XmlData as FromSql>::from_sql(&data).unwrap_err();
        assert!(format!("{}", err).contains("cannot interpret"));
    }

    #[test]
    fn string_owned_and_borrowed_str() {
        let data = ColumnData::String(Some(std::borrow::Cow::Borrowed("hello")));
        let borrowed = <&str as FromSql>::from_sql(&data).unwrap();
        assert_eq!(Some("hello"), borrowed);

        let owned = String::from_sql_owned(data).unwrap();
        assert_eq!(Some("hello".to_string()), owned);
    }

    #[test]
    fn string_wrong_variant_errors() {
        let data = ColumnData::I32(Some(1));
        let err = String::from_sql_owned(data).unwrap_err();
        assert!(format!("{}", err).contains("cannot interpret"));

        let data = ColumnData::I32(Some(1));
        let err = <&str as FromSql>::from_sql(&data).unwrap_err();
        assert!(format!("{}", err).contains("cannot interpret"));
    }

    #[test]
    fn binary_owned_and_borrowed_slice() {
        let bytes = vec![1u8, 2, 3];
        let data = ColumnData::Binary(Some(std::borrow::Cow::Owned(bytes.clone())));

        let borrowed = <&[u8] as FromSql>::from_sql(&data).unwrap();
        assert_eq!(Some(bytes.as_slice()), borrowed);

        let owned = Vec::<u8>::from_sql_owned(data).unwrap();
        assert_eq!(Some(bytes), owned);
    }

    #[test]
    fn binary_wrong_variant_errors() {
        let data = ColumnData::I32(Some(1));
        let err = Vec::<u8>::from_sql_owned(data).unwrap_err();
        assert!(format!("{}", err).contains("cannot interpret"));

        let data = ColumnData::I32(Some(1));
        let err = <&[u8] as FromSql>::from_sql(&data).unwrap_err();
        assert!(format!("{}", err).contains("cannot interpret"));
    }

    #[test]
    fn null_string_and_binary_values() {
        let data = ColumnData::String(None);
        assert_eq!(None, String::from_sql_owned(data).unwrap());

        let data = ColumnData::Binary(None);
        assert_eq!(None, Vec::<u8>::from_sql_owned(data).unwrap());

        let data = ColumnData::Xml(None);
        assert_eq!(None, XmlData::from_sql_owned(data).unwrap());
    }
}
