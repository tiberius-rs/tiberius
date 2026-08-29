//! Tests that verify the optional serde Serialize/Deserialize impls
//! gated behind the `serde` feature.
//!
//! These tests do not require a live SQL Server. They round-trip the
//! exposed result-set types (Row pieces, ColumnData, Numeric, time
//! types, etc.) through `serde_json` and assert the values survive.

#![cfg(feature = "serde")]

use std::borrow::Cow;
use std::sync::Arc;

use tiberius::numeric::Numeric;
use tiberius::time::DateTime;
use tiberius::xml::XmlData;
use tiberius::{Column, ColumnData, ColumnType, TokenRow};
use uuid::Uuid;

#[cfg(feature = "tds73")]
use tiberius::time::{Date, DateTime2, DateTimeOffset, Time};

fn json_round_trip<T>(value: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let s = serde_json::to_string(value).expect("serialize");
    serde_json::from_str(&s).expect("deserialize")
}

#[test]
fn column_type_round_trip() {
    let value = ColumnType::Int4;
    let back: ColumnType = json_round_trip(&value);
    assert_eq!(value, back);
}

#[test]
fn column_round_trip() {
    let value = Column::new("hello".to_string(), ColumnType::NVarchar);
    let back: Column = json_round_trip(&value);
    assert_eq!(back.name(), "hello");
    assert_eq!(back.column_type(), ColumnType::NVarchar);
}

#[test]
fn column_data_int_round_trip() {
    let value = ColumnData::I32(Some(42));
    let back: ColumnData<'static> = json_round_trip(&value);
    assert_eq!(value, back);
}

#[test]
fn column_data_null_round_trip() {
    let value: ColumnData<'static> = ColumnData::I64(None);
    let back: ColumnData<'static> = json_round_trip(&value);
    assert_eq!(value, back);
}

#[test]
fn column_data_string_round_trip() {
    let value = ColumnData::String(Some(Cow::Borrowed("héllo")));
    let back: ColumnData<'static> = json_round_trip(&value);
    // Borrowed inputs deserialize as Cow::Owned but values match.
    match back {
        ColumnData::String(Some(s)) => assert_eq!(s.as_ref(), "héllo"),
        other => panic!("unexpected: {:?}", other),
    }
}

#[test]
fn column_data_binary_round_trip() {
    let bytes: &[u8] = &[0xde, 0xad, 0xbe, 0xef];
    let value = ColumnData::Binary(Some(Cow::Borrowed(bytes)));
    let back: ColumnData<'static> = json_round_trip(&value);
    match back {
        ColumnData::Binary(Some(b)) => assert_eq!(b.as_ref(), bytes),
        other => panic!("unexpected: {:?}", other),
    }
}

#[test]
fn column_data_guid_round_trip() {
    let id = Uuid::from_u128(0xfeed_face_dead_beef_0000_1111_2222_3333u128);
    let value = ColumnData::Guid(Some(id));
    let back: ColumnData<'static> = json_round_trip(&value);
    assert_eq!(value, back);
}

#[test]
fn column_data_bool_round_trip() {
    let value = ColumnData::Bit(Some(true));
    let back: ColumnData<'static> = json_round_trip(&value);
    assert_eq!(value, back);
}

#[test]
fn column_data_float_round_trip() {
    let value = ColumnData::F64(Some(std::f64::consts::PI));
    let back: ColumnData<'static> = json_round_trip(&value);
    assert_eq!(value, back);
}

#[test]
fn numeric_round_trip() {
    let value = Numeric::new_with_scale(57705, 2);
    let back: Numeric = json_round_trip(&value);
    assert_eq!(value, back);
    assert_eq!(back.value(), 57705);
    assert_eq!(back.scale(), 2);
}

#[test]
fn column_data_numeric_round_trip() {
    let value = ColumnData::Numeric(Some(Numeric::new_with_scale(12345, 3)));
    let back: ColumnData<'static> = json_round_trip(&value);
    assert_eq!(value, back);
}

#[test]
fn datetime_round_trip() {
    let value = DateTime::new(200, 3000);
    let back: DateTime = json_round_trip(&value);
    assert_eq!(value, back);
}

#[test]
fn column_data_datetime_round_trip() {
    let value = ColumnData::DateTime(Some(DateTime::new(42, 84)));
    let back: ColumnData<'static> = json_round_trip(&value);
    assert_eq!(value, back);
}

#[cfg(feature = "tds73")]
#[test]
fn time_types_round_trip() {
    let date = Date::new(123);
    let time = Time::new(7, 7);
    let dt2 = DateTime2::new(date, time);
    let dto = DateTimeOffset::new(dt2, -120);

    assert_eq!(date, json_round_trip(&date));
    assert_eq!(time, json_round_trip(&time));
    assert_eq!(dt2, json_round_trip(&dt2));
    assert_eq!(dto, json_round_trip(&dto));
}

#[test]
fn xml_data_round_trip() {
    let value = XmlData::new("<root>hi</root>");
    let back: XmlData = json_round_trip(&value);
    assert_eq!(value.as_ref(), back.as_ref());
}

#[test]
fn token_row_round_trip() {
    let mut row: TokenRow<'static> = TokenRow::new();
    row.push(ColumnData::I32(Some(1)));
    row.push(ColumnData::String(Some(Cow::Owned("hello".to_string()))));
    row.push(ColumnData::Bit(Some(false)));

    let back: TokenRow<'static> = json_round_trip(&row);
    assert_eq!(back.len(), 3);
    assert_eq!(back.get(0), Some(&ColumnData::I32(Some(1))));
    match back.get(1).unwrap() {
        ColumnData::String(Some(s)) => assert_eq!(s.as_ref(), "hello"),
        other => panic!("unexpected: {:?}", other),
    }
    assert_eq!(back.get(2), Some(&ColumnData::Bit(Some(false))));
}

/// Mimic the "send query results across the network as JSON" flow from
/// the issue: build a row out of columns + data, then verify the whole
/// thing round-trips.
#[test]
fn row_shape_round_trip() {
    // Build column metadata.
    let columns = Arc::new(vec![
        Column::new("id".to_string(), ColumnType::Int4),
        Column::new("name".to_string(), ColumnType::NVarchar),
    ]);
    let mut data: TokenRow<'static> = TokenRow::new();
    data.push(ColumnData::I32(Some(7)));
    data.push(ColumnData::String(Some(Cow::Owned("ada".to_string()))));

    // Round-trip the column metadata.
    let columns_back: Arc<Vec<Column>> = json_round_trip(&columns);
    assert_eq!(columns_back.len(), 2);
    assert_eq!(columns_back[0].name(), "id");
    assert_eq!(columns_back[1].column_type(), ColumnType::NVarchar);

    // Round-trip the row data.
    let data_back: TokenRow<'static> = json_round_trip(&data);
    assert_eq!(data_back.len(), 2);
    assert_eq!(data_back.get(0), Some(&ColumnData::I32(Some(7))));
}
