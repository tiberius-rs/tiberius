pub(crate) struct FieldAttr {
    pub colname: Option<String>,
}

impl FieldAttr {
    pub(crate) fn parse(attrs: &[syn::Attribute]) -> Option<FieldAttr> {
        let mut result = None;
        for attr in attrs.iter() {
            match attr.style {
                syn::AttrStyle::Outer => {}
                _ => continue,
            }
            let last_attr_path = attr
                .path()
                .segments
                .last()
                .expect("Expected at least one segment where #[segment[::segment*](..)]");
            if last_attr_path.ident != "colname" {
                continue;
            }
            let kv = match attr.meta {
                syn::Meta::NameValue(ref kv) => kv,
                _ if attr.path().is_ident("colname") => {
                    panic!("Invalid #[colname] attribute, expected #[colname = \"SomeColName\"]")
                }
                _ => continue,
            };
            if result.is_some() {
                panic!("Expected at most one #[colname] attribute");
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
                panic!("Non-string literal value in #[colname] attribute");
            }
        }
        result
    }
}
