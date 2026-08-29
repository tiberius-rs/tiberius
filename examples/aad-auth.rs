//! Use AAD-Auth to connect to SQL server.
//!
//! To Setup:
//! - Follow this [link](https://docs.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-configure?view=azuresql&tabs=azure-powershell) to setup your Azure SQL with AAD auth;
//! - Create an AAD Service Principal [link](https://docs.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-service-principal?view=azuresql) and configure it to access your SQL instance;
//! - Setup the environment variable with:
//!   - CLIENT_ID: service principal ID;
//!   - CLIENT_SECRET: service principal secret;
//!   - TENANT_ID: tenant id of service principal and sql instance;
//!   - SERVER: SQL server URI
use azure_core::credentials::{Secret, TokenCredential};
use azure_identity::ClientSecretCredential;
use std::env;
use tiberius::{AuthMethod, Client, Config, Query};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client_id = env::var("CLIENT_ID").expect("Missing CLIENT_ID environment variable.");
    let client_secret =
        env::var("CLIENT_SECRET").expect("Missing CLIENT_SECRET environment variable.");
    let tenant_id = env::var("TENANT_ID").expect("Missing TENANT_ID environment variable.");

    let credential =
        ClientSecretCredential::new(&tenant_id, client_id, Secret::new(client_secret), None)?;

    let token = credential
        .get_token(&["https://database.windows.net/.default"], None)
        .await?;

    let mut config = Config::new();
    let server = env::var("SERVER").expect("Missing SERVER environment variable.");
    config.host(server);
    config.port(1433);
    config.authentication(AuthMethod::AADToken(token.token.secret().to_owned()));
    config.trust_cert();

    let tcp = TcpStream::connect(config.get_addr()).await?;
    tcp.set_nodelay(true)?;

    let mut client = Client::connect(config, tcp.compat_write()).await?;
    let params = vec![String::from("foo"), String::from("bar")];
    let mut select = Query::new("SELECT @P1, @P2, @P3");

    for param in params.into_iter() {
        select.bind(param);
    }

    let _res = select.query(&mut client).await?;

    Ok(())
}
