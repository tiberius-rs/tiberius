use super::codec::*;
use std::collections::HashMap;
use std::sync::Arc;

/// Context, that might be required to make sure we understand and are understood by the server
#[derive(Debug)]
pub(crate) struct Context {
    version: FeatureLevel,
    packet_size: u32,
    packet_id: u8,
    transaction_desc: [u8; 8],
    last_meta: Option<Arc<TokenColMetaData<'static>>>,
    /// Metadata for COMPUTE (BY) result sets (`ALTMETADATA`), keyed by the
    /// COMPUTE clause id that the matching `ALTROW` rows refer back to.
    alt_metas: HashMap<u16, Arc<TokenAltMetaData<'static>>>,
    spn: Option<String>,
}

impl Context {
    pub fn new() -> Context {
        Context {
            version: FeatureLevel::SqlServerN,
            packet_size: 4096,
            packet_id: 0,
            transaction_desc: [0; 8],
            last_meta: None,
            alt_metas: HashMap::new(),
            spn: None,
        }
    }

    pub fn next_packet_id(&mut self) -> u8 {
        let id = self.packet_id;
        self.packet_id = self.packet_id.wrapping_add(1);
        id
    }

    pub fn set_last_meta(&mut self, meta: Arc<TokenColMetaData<'static>>) {
        self.last_meta.replace(meta);
    }

    pub fn last_meta(&self) -> Option<Arc<TokenColMetaData<'static>>> {
        self.last_meta.clone()
    }

    /// Stores the metadata for a COMPUTE (BY) result set, keyed by its id, so
    /// that a following `ALTROW` token can be decoded.
    pub fn set_alt_meta(&mut self, meta: Arc<TokenAltMetaData<'static>>) {
        self.alt_metas.insert(meta.id, meta);
    }

    /// Retrieves previously seen COMPUTE (BY) metadata by its id.
    pub fn alt_meta(&self, id: u16) -> Option<Arc<TokenAltMetaData<'static>>> {
        self.alt_metas.get(&id).cloned()
    }

    pub fn packet_size(&self) -> u32 {
        self.packet_size
    }

    pub fn set_packet_size(&mut self, new_size: u32) {
        self.packet_size = new_size;
    }

    pub fn transaction_descriptor(&self) -> [u8; 8] {
        self.transaction_desc
    }

    pub fn set_transaction_descriptor(&mut self, desc: [u8; 8]) {
        self.transaction_desc = desc;
    }

    /// Overrides the negotiated protocol version. Used by tests to exercise
    /// version-dependent decode paths (e.g. the pre-2005 4-byte DONE rowcount).
    #[cfg(test)]
    pub(crate) fn set_version(&mut self, version: FeatureLevel) {
        self.version = version;
    }

    pub fn version(&self) -> FeatureLevel {
        self.version
    }

    pub fn set_spn(&mut self, host: impl AsRef<str>, port: u16) {
        self.spn = Some(format!("MSSQLSvc/{}:{}", host.as_ref(), port));
    }

    #[cfg(any(
        windows,
        all(unix, any(feature = "integrated-auth-gssapi", feature = "sspi-rs"))
    ))]
    pub fn spn(&self) -> &str {
        self.spn.as_deref().unwrap_or("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_has_expected_defaults() {
        let ctx = Context::new();
        assert_eq!(ctx.packet_size(), 4096);
        assert_eq!(ctx.transaction_descriptor(), [0; 8]);
        assert!(ctx.last_meta().is_none());
        assert!(ctx.alt_meta(0).is_none());
    }

    #[test]
    fn next_packet_id_increments_and_wraps() {
        let mut ctx = Context::new();
        assert_eq!(ctx.next_packet_id(), 0);
        assert_eq!(ctx.next_packet_id(), 1);
        assert_eq!(ctx.next_packet_id(), 2);

        // Force a wraparound to make sure it doesn't panic on overflow.
        for _ in 0..252 {
            ctx.next_packet_id();
        }
        assert_eq!(ctx.next_packet_id(), 255);
        assert_eq!(ctx.next_packet_id(), 0);
    }

    #[test]
    fn set_and_get_packet_size() {
        let mut ctx = Context::new();
        ctx.set_packet_size(8192);
        assert_eq!(ctx.packet_size(), 8192);
    }

    #[test]
    fn set_and_get_transaction_descriptor() {
        let mut ctx = Context::new();
        let desc = [1, 2, 3, 4, 5, 6, 7, 8];
        ctx.set_transaction_descriptor(desc);
        assert_eq!(ctx.transaction_descriptor(), desc);
    }

    #[test]
    fn set_and_get_last_meta() {
        let mut ctx = Context::new();
        let meta = Arc::new(TokenColMetaData { columns: vec![] });
        ctx.set_last_meta(meta.clone());

        let got = ctx.last_meta().unwrap();
        assert_eq!(got.columns.len(), meta.columns.len());
    }

    #[test]
    fn set_and_get_alt_meta_by_id() {
        let mut ctx = Context::new();
        let meta = Arc::new(TokenAltMetaData {
            id: 7,
            by_columns: vec![1, 2],
            columns: vec![],
        });
        ctx.set_alt_meta(meta.clone());

        let got = ctx.alt_meta(7).unwrap();
        assert_eq!(got.id, 7);
        assert_eq!(got.by_columns, vec![1, 2]);

        // A different id should still be absent.
        assert!(ctx.alt_meta(8).is_none());
    }

    #[test]
    fn version_defaults_to_sql_server_n() {
        let ctx = Context::new();
        assert_eq!(ctx.version(), FeatureLevel::SqlServerN);
    }

    #[test]
    fn set_spn_formats_service_principal_name() {
        let mut ctx = Context::new();
        ctx.set_spn("dbhost", 1433);

        #[cfg(any(
            windows,
            all(unix, any(feature = "integrated-auth-gssapi", feature = "sspi-rs"))
        ))]
        assert_eq!(ctx.spn(), "MSSQLSvc/dbhost:1433");

        // On platforms without an spn() accessor, at least make sure setting
        // it doesn't panic.
        #[cfg(not(any(
            windows,
            all(unix, any(feature = "integrated-auth-gssapi", feature = "sspi-rs"))
        )))]
        let _ = ctx;
    }
}
