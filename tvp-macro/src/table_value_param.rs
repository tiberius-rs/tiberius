use proc_macro2::TokenStream;
use syn::punctuated::Punctuated;

use crate::attr::FieldAttr;

pub(crate) fn for_struct(ast: &syn::DeriveInput, fields: &syn::Fields) -> TokenStream {
    match *fields {
        syn::Fields::Named(ref fields) => table_value_param_impl(ast, Some(&fields.named)),
        _ => panic!("Only named fields are supported so far"),
    }
}

fn table_value_param_impl(
    ast: &syn::DeriveInput,
    fields: Option<&Punctuated<syn::Field, Token![,]>>,
) -> TokenStream {
    let name = &ast.ident;
    let (lt_impl, lt_struct) = {
        let mut lifetimes: Vec<&syn::Ident> = Vec::new();
        for gp in ast.generics.params.iter() {
            if let syn::GenericParam::Lifetime(ltp) = gp {
                lifetimes.push(&ltp.lifetime.ident);
            }
        }
        if lifetimes.len() > 1 {
            panic!(
                "Only one lifetime specifier is supported for the structure. Found multiple: {}",
                lifetimes
                    .iter()
                    .map(|lt| lt.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if lifetimes.is_empty() {
            (sp_quote!(<'query>), sp_quote!())
        } else {
            let lt = lifetimes[0];
            let ts: proc_macro2::TokenStream = format!("< '{} >", lt).parse().unwrap();
            (ts.clone(), ts)
        }
    };
    let empty = Default::default();
    let fields: Vec<_> = fields.unwrap_or(&empty).iter().map(FieldExt::new).collect();
    let col_names: Vec<_> = fields.iter().map(|f| f.get_col_name()).collect();
    // Column names are not needed for stored procedures, but will be required
    // once TVPs are supported for ad-hoc queries.
    let _col_names = sp_quote!( #(#col_names),* );
    let col_binds: Vec<_> = fields.iter().map(|f| f.as_bind()).collect();
    let col_binds = sp_quote!( #(#col_binds);*);
    sp_quote! {
        impl #lt_impl tiberius::TableValueRow #lt_impl for #name #lt_struct {
            fn get_db_type() -> &'static str {
                stringify!{ #name }
            }

            fn bind_fields(&self, data_row: &mut tiberius::SqlTableDataRow #lt_impl) {
                #col_binds;
            }
        }
    }
}

struct FieldExt {
    attr: Option<FieldAttr>,
    ident: syn::Ident,
}

impl FieldExt {
    pub fn new(field: &syn::Field) -> FieldExt {
        if let Some(ident) = field.ident.clone() {
            FieldExt {
                attr: FieldAttr::parse(&field.attrs),
                ident,
            }
        } else {
            panic!("Field ident is required");
        }
    }
    pub(crate) fn get_col_name(&self) -> String {
        if let Some(attr) = self.attr.as_ref() {
            if let Some(colname) = attr.colname.as_ref() {
                return colname.to_string();
            }
        }
        self.ident.to_string()
    }
    pub(crate) fn as_bind(&self) -> TokenStream {
        let name = &self.ident;
        sp_quote!(data_row.add_field(self.#name))
    }
}

#[cfg(test)]
mod tests {
    use super::for_struct;

    #[test]
    fn basic_nolifetime() {
        let ast: syn::DeriveInput = syn::parse_str(
            r#"
    pub struct SomeGeoList {
        #[colname = "SomeID"]
        pub id: i32,
        #[colname = "LastSyncIPGeoLat"]
        pub lat: Numeric, // decimal(9,6)
        #[colname = "LastSyncIPGeoLong"]
        pub lon: Numeric, // decimal(9,6)
    }
            "#,
        )
        .unwrap();
        let result = match ast.data {
            syn::Data::Enum(_) => panic!("n/a for enums, makes sense for structs only"),
            syn::Data::Struct(ref s) => for_struct(&ast, &s.fields),
            syn::Data::Union(_) => panic!("doesn't work with unions"),
        };
        let etalon = sp_quote!(
            impl<'query> tiberius::TableValueRow<'query> for SomeGeoList {
                fn get_db_type() -> &'static str {
                    stringify! { SomeGeoList }
                }
                fn bind_fields(&self, data_row: &mut tiberius::SqlTableDataRow<'query>) {
                    data_row.add_field(self.id);
                    data_row.add_field(self.lat);
                    data_row.add_field(self.lon);
                }
            }
        );

        assert_eq!(result.to_string(), etalon.to_string());
    }

    #[test]
    fn basic_lifetime() {
        let ast: syn::DeriveInput = syn::parse_str(
            r#"
    pub struct AnotherGeoList<'e> {
        #[colname = "SomeID"]
        pub id: i32,
        #[colname = "SomeStr"]
        pub s: &'e str,
    }
            "#,
        )
        .unwrap();
        let result = match ast.data {
            syn::Data::Enum(_) => panic!("n/a for enums, makes sense for structs only"),
            syn::Data::Struct(ref s) => for_struct(&ast, &s.fields),
            syn::Data::Union(_) => panic!("doesn't work with unions"),
        };

        let etalon = sp_quote!(
            impl<'e> tiberius::TableValueRow<'e> for AnotherGeoList<'e> {
                fn get_db_type() -> &'static str {
                    stringify! { AnotherGeoList }
                }
                fn bind_fields(&self, data_row: &mut tiberius::SqlTableDataRow<'e>) {
                    data_row.add_field(self.id);
                    data_row.add_field(self.s);
                }
            }
        );

        assert_eq!(result.to_string(), etalon.to_string());
    }
}
