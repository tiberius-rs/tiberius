//! A utility proc-macro crate that generates trivial trait implementations used
//! in the Rust-to-SQL data exchange for tiberius table-valued parameters.
extern crate proc_macro;

#[macro_use]
extern crate quote;
#[macro_use]
extern crate syn;

use proc_macro::TokenStream;

macro_rules! sp_quote {
    ($($t:tt)*) => (quote_spanned!(proc_macro2::Span::call_site() => $($t)*))
}

mod attr;
mod table_value_param;

/// Generates a trivial implementation of the `TableValueRow` trait.
///
/// # Applications
/// Apply to structs that represent rows of a table-valued parameter.
///
/// # Example
/// ```rust,ignore
/// # use tiberius::*;
/// #[derive(TableValueRow)]
/// pub struct SomeGeoList {
///   #[colname = "SomeID"]
///   pub id: i32,
///   #[colname = "LastSyncIPGeoLat"]
///   pub lat: Numeric,
///   #[colname = "LastSyncIPGeoLong"]
///   pub lon: Numeric,
/// }
/// ```
///
/// # Supported field types
///
/// Each field is bound with `SqlTableDataRow::add_field(self.<field>)`, so the
/// field type must implement `IntoSql` *by value*. That covers the `Copy`
/// scalar/marker types (`i32`, `i64`, `bool`, `f64`, `Numeric`, `Uuid`, …) and
/// borrowed strings/bytes (`&str`, `&[u8]`). Owned, non-`Copy` columns such as
/// `String` or `Vec<u8>` cannot be moved out of `&self`; model those columns as
/// `&str` / `&[u8]` (with a struct lifetime) instead.
#[proc_macro_derive(TableValueRow, attributes(colname))]
pub fn table_value_param(input: TokenStream) -> TokenStream {
    let ast: syn::DeriveInput = match syn::parse(input) {
        Ok(ast) => ast,
        Err(e) => return e.to_compile_error().into(),
    };

    let result = match ast.data {
        syn::Data::Struct(ref s) => table_value_param::for_struct(&ast, &s.fields),
        syn::Data::Enum(_) => Err(syn::Error::new_spanned(
            &ast.ident,
            "TableValueRow can only be derived for structs, not enums",
        )),
        syn::Data::Union(_) => Err(syn::Error::new_spanned(
            &ast.ident,
            "TableValueRow can only be derived for structs, not unions",
        )),
    };

    match result {
        Ok(tokens) => tokens.into(),
        Err(e) => e.to_compile_error().into(),
    }
}
