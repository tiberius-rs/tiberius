pub(crate) struct FieldAttr {
    pub colname: Option<String>,
}

impl FieldAttr {
    pub(crate) fn parse(attrs: &[syn::Attribute]) -> syn::Result<Option<FieldAttr>> {
        let mut result = None;
        for attr in attrs.iter() {
            match attr.style {
                syn::AttrStyle::Outer => {}
                _ => continue,
            }
            // A parsed attribute path always has at least one segment, so this
            // is effectively infallible; keep an explicit guard just in case.
            let Some(last_attr_path) = attr.path().segments.last() else {
                continue;
            };
            if last_attr_path.ident != "colname" {
                continue;
            }
            let kv = match attr.meta {
                syn::Meta::NameValue(ref kv) => kv,
                _ if attr.path().is_ident("colname") => {
                    return Err(syn::Error::new_spanned(
                        attr,
                        "invalid `#[colname]` attribute on a `#[derive(TableValueRow)]` field: \
                         expected the form `#[colname = \"SomeColName\"]`",
                    ));
                }
                _ => continue,
            };
            if result.is_some() {
                return Err(syn::Error::new_spanned(
                    attr,
                    "duplicate `#[colname]` attribute on a `#[derive(TableValueRow)]` field: \
                     at most one `#[colname = \"...\"]` is allowed per field",
                ));
            }
            if let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(ref s),
                ..
            }) = kv.value
            {
                result = Some(FieldAttr {
                    colname: Some(s.value()),
                });
            } else {
                return Err(syn::Error::new_spanned(
                    &kv.value,
                    "invalid `#[colname]` value on a `#[derive(TableValueRow)]` field: \
                     expected a string literal, as in `#[colname = \"SomeColName\"]`",
                ));
            }
        }
        Ok(result)
    }
}
