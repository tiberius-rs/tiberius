//! Internal test-only proc-macro for tiberius.
//!
//! `#[test_on_runtimes]` takes an `async fn(client) -> Result<()>` and generates
//! one integration test per supported async runtime, so every test proves the
//! (runtime-independent) driver works on each of them. Currently: **tokio** and
//! **smol**.
extern crate proc_macro;

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, ItemFn, LitStr};

/// Optional `connection_string = "IDENT"` attribute argument naming the `&str`
/// constant to connect with. Defaults to `CONN_STR`.
struct Args {
    conn_str: String,
}

impl syn::parse::Parse for Args {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
        let mut conn_str = String::from("CONN_STR");

        if !input.is_empty() {
            let ident: syn::Ident = input.parse()?;
            if ident != "connection_string" {
                return Err(syn::Error::new(
                    ident.span(),
                    "expected `connection_string = \"...\"`",
                ));
            }
            input.parse::<syn::Token![=]>()?;
            let lit: LitStr = input.parse()?;
            conn_str = lit.value();
        }

        Ok(Args { conn_str })
    }
}

#[proc_macro_attribute]
pub fn test_on_runtimes(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as Args);
    let func = parse_macro_input!(input as ItemFn);

    let conn_str_ident = format_ident!("{}", args.conn_str);
    let func_name = func.sig.ident.clone();
    let tokio_test = format_ident!("{}_tokio", func_name);
    let smol_test = format_ident!("{}_smol", func_name);

    let tokens = quote! {
        #func

        #[test]
        fn #tokio_test() -> Result<()> {
            LOGGER_SETUP.call_once(|| {
                let _ = env_logger::builder().is_test(true).try_init();
            });

            use tokio_util::compat::TokioAsyncWriteCompatExt;

            let rt = tokio::runtime::Runtime::new()?;

            rt.block_on(async {
                let config = tiberius::Config::from_ado_string(&#conn_str_ident)?;
                let tcp = tokio::net::TcpStream::connect(config.get_addr()).await?;
                tcp.set_nodelay(true)?;
                let client = tiberius::Client::connect(config, tcp.compat_write()).await?;

                #func_name(client).await?;
                Ok(())
            })
        }

        #[test]
        fn #smol_test() -> Result<()> {
            LOGGER_SETUP.call_once(|| {
                let _ = env_logger::builder().is_test(true).try_init();
            });

            smol::block_on(async {
                let config = tiberius::Config::from_ado_string(&#conn_str_ident)?;
                let tcp = smol::net::TcpStream::connect(config.get_addr()).await?;
                tcp.set_nodelay(true)?;
                let client = tiberius::Client::connect(config, tcp).await?;

                #func_name(client).await?;
                Ok(())
            })
        }
    };

    TokenStream::from(tokens)
}
