use crate::{IntoSql, TokenRow};

/// create a TokenRow from list of values
pub trait IntoRow<'a> {
    /// create a TokenRow from list of values which implements IntoSQL
    fn into_row(self) -> TokenRow<'a>;
}

impl<'a, A> IntoRow<'a> for A
where
    A: IntoSql<'a>,
{
    fn into_row(self) -> TokenRow<'a> {
        let mut row = TokenRow::with_capacity(1);
        row.push(self.into_sql());
        row
    }
}

impl<'a, A, B> IntoRow<'a> for (A, B)
where
    A: IntoSql<'a>,
    B: IntoSql<'a>,
{
    fn into_row(self) -> TokenRow<'a> {
        let mut row = TokenRow::with_capacity(2);
        row.push(self.0.into_sql());
        row.push(self.1.into_sql());
        row
    }
}

impl<'a, A, B, C> IntoRow<'a> for (A, B, C)
where
    A: IntoSql<'a>,
    B: IntoSql<'a>,
    C: IntoSql<'a>,
{
    fn into_row(self) -> TokenRow<'a> {
        let mut row = TokenRow::with_capacity(3);
        row.push(self.0.into_sql());
        row.push(self.1.into_sql());
        row.push(self.2.into_sql());
        row
    }
}

impl<'a, A, B, C, D> IntoRow<'a> for (A, B, C, D)
where
    A: IntoSql<'a>,
    B: IntoSql<'a>,
    C: IntoSql<'a>,
    D: IntoSql<'a>,
{
    fn into_row(self) -> TokenRow<'a> {
        let mut row = TokenRow::with_capacity(4);
        row.push(self.0.into_sql());
        row.push(self.1.into_sql());
        row.push(self.2.into_sql());
        row.push(self.3.into_sql());
        row
    }
}

impl<'a, A, B, C, D, E> IntoRow<'a> for (A, B, C, D, E)
where
    A: IntoSql<'a>,
    B: IntoSql<'a>,
    C: IntoSql<'a>,
    D: IntoSql<'a>,
    E: IntoSql<'a>,
{
    fn into_row(self) -> TokenRow<'a> {
        let mut row = TokenRow::with_capacity(5);
        row.push(self.0.into_sql());
        row.push(self.1.into_sql());
        row.push(self.2.into_sql());
        row.push(self.3.into_sql());
        row.push(self.4.into_sql());
        row
    }
}

impl<'a, A, B, C, D, E, F> IntoRow<'a> for (A, B, C, D, E, F)
where
    A: IntoSql<'a>,
    B: IntoSql<'a>,
    C: IntoSql<'a>,
    D: IntoSql<'a>,
    E: IntoSql<'a>,
    F: IntoSql<'a>,
{
    fn into_row(self) -> TokenRow<'a> {
        let mut row = TokenRow::with_capacity(6);
        row.push(self.0.into_sql());
        row.push(self.1.into_sql());
        row.push(self.2.into_sql());
        row.push(self.3.into_sql());
        row.push(self.4.into_sql());
        row.push(self.5.into_sql());
        row
    }
}

impl<'a, A, B, C, D, E, F, G> IntoRow<'a> for (A, B, C, D, E, F, G)
where
    A: IntoSql<'a>,
    B: IntoSql<'a>,
    C: IntoSql<'a>,
    D: IntoSql<'a>,
    E: IntoSql<'a>,
    F: IntoSql<'a>,
    G: IntoSql<'a>,
{
    fn into_row(self) -> TokenRow<'a> {
        let mut row = TokenRow::with_capacity(7);
        row.push(self.0.into_sql());
        row.push(self.1.into_sql());
        row.push(self.2.into_sql());
        row.push(self.3.into_sql());
        row.push(self.4.into_sql());
        row.push(self.5.into_sql());
        row.push(self.6.into_sql());
        row
    }
}

impl<'a, A, B, C, D, E, F, G, H> IntoRow<'a> for (A, B, C, D, E, F, G, H)
where
    A: IntoSql<'a>,
    B: IntoSql<'a>,
    C: IntoSql<'a>,
    D: IntoSql<'a>,
    E: IntoSql<'a>,
    F: IntoSql<'a>,
    G: IntoSql<'a>,
    H: IntoSql<'a>,
{
    fn into_row(self) -> TokenRow<'a> {
        let mut row = TokenRow::with_capacity(8);
        row.push(self.0.into_sql());
        row.push(self.1.into_sql());
        row.push(self.2.into_sql());
        row.push(self.3.into_sql());
        row.push(self.4.into_sql());
        row.push(self.5.into_sql());
        row.push(self.6.into_sql());
        row.push(self.7.into_sql());
        row
    }
}

impl<'a, A, B, C, D, E, F, G, H, I> IntoRow<'a> for (A, B, C, D, E, F, G, H, I)
where
    A: IntoSql<'a>,
    B: IntoSql<'a>,
    C: IntoSql<'a>,
    D: IntoSql<'a>,
    E: IntoSql<'a>,
    F: IntoSql<'a>,
    G: IntoSql<'a>,
    H: IntoSql<'a>,
    I: IntoSql<'a>,
{
    fn into_row(self) -> TokenRow<'a> {
        let mut row = TokenRow::with_capacity(9);
        row.push(self.0.into_sql());
        row.push(self.1.into_sql());
        row.push(self.2.into_sql());
        row.push(self.3.into_sql());
        row.push(self.4.into_sql());
        row.push(self.5.into_sql());
        row.push(self.6.into_sql());
        row.push(self.7.into_sql());
        row.push(self.8.into_sql());
        row
    }
}

impl<'a, A, B, C, D, E, F, G, H, I, J> IntoRow<'a> for (A, B, C, D, E, F, G, H, I, J)
where
    A: IntoSql<'a>,
    B: IntoSql<'a>,
    C: IntoSql<'a>,
    D: IntoSql<'a>,
    E: IntoSql<'a>,
    F: IntoSql<'a>,
    G: IntoSql<'a>,
    H: IntoSql<'a>,
    I: IntoSql<'a>,
    J: IntoSql<'a>,
{
    fn into_row(self) -> TokenRow<'a> {
        let mut row = TokenRow::with_capacity(10);
        row.push(self.0.into_sql());
        row.push(self.1.into_sql());
        row.push(self.2.into_sql());
        row.push(self.3.into_sql());
        row.push(self.4.into_sql());
        row.push(self.5.into_sql());
        row.push(self.6.into_sql());
        row.push(self.7.into_sql());
        row.push(self.8.into_sql());
        row.push(self.9.into_sql());
        row
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tds::codec::ColumnData;

    #[test]
    fn single_value_into_row() {
        let row = 42i32.into_row();
        assert_eq!(row.len(), 1);
        assert_eq!(row.get(0), Some(&ColumnData::I32(Some(42))));
    }

    #[test]
    fn tuple_arities_produce_expected_lengths_and_order() {
        assert_eq!((1i32, 2i32).into_row().len(), 2);
        assert_eq!((1i32, 2i32, 3i32).into_row().len(), 3);
        assert_eq!((1i32, 2i32, 3i32, 4i32).into_row().len(), 4);
        assert_eq!((1i32, 2i32, 3i32, 4i32, 5i32).into_row().len(), 5);
        assert_eq!((1i32, 2i32, 3i32, 4i32, 5i32, 6i32).into_row().len(), 6);
        assert_eq!(
            (1i32, 2i32, 3i32, 4i32, 5i32, 6i32, 7i32).into_row().len(),
            7
        );
        assert_eq!(
            (1i32, 2i32, 3i32, 4i32, 5i32, 6i32, 7i32, 8i32)
                .into_row()
                .len(),
            8
        );
        assert_eq!(
            (1i32, 2i32, 3i32, 4i32, 5i32, 6i32, 7i32, 8i32, 9i32)
                .into_row()
                .len(),
            9
        );

        let row = (1i32, 2i32, 3i32, 4i32, 5i32, 6i32, 7i32, 8i32, 9i32, 10i32).into_row();
        assert_eq!(row.len(), 10);

        // Values are pushed in tuple order.
        for (i, value) in row.iter().enumerate() {
            assert_eq!(value, &ColumnData::I32(Some(i as i32 + 1)));
        }
    }

    #[test]
    fn mixed_types_preserve_positions() {
        let row = (true, 7u8, "hello", 3.5f64).into_row();
        assert_eq!(row.len(), 4);
        assert_eq!(row.get(0), Some(&ColumnData::Bit(Some(true))));
        assert_eq!(row.get(1), Some(&ColumnData::U8(Some(7))));
        assert_eq!(row.get(3), Some(&ColumnData::F64(Some(3.5))));
    }
}
