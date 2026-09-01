use super::Encode;
use byteorder::{LittleEndian, WriteBytesExt};
use bytes::BytesMut;
use enumflags2::{bitflags, BitFlags};
use io::{Cursor, Write};
use std::fmt::Debug;
use std::{borrow::Cow, io};
use zeroize::{Zeroize, Zeroizing};

uint_enum! {
    #[repr(u32)]
    #[derive(PartialOrd, Default)]
    pub enum FeatureLevel {
        SqlServerV7 = 0x70000000,
        SqlServer2000 = 0x71000000,
        SqlServer2000Sp1 = 0x71000001,
        SqlServer2005 = 0x72090002,
        SqlServer2008 = 0x730A0003,
        SqlServer2008R2 = 0x730B0003,
        /// 2012, 2014, 2016
        #[default]
        SqlServerN = 0x74000004,
    }
}

impl FeatureLevel {
    pub fn done_row_count_bytes(self) -> u8 {
        if self as u32 >= FeatureLevel::SqlServer2005 as u32 {
            8
        } else {
            4
        }
    }
}

#[bitflags]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionFlag1 {
    /// The byte order used by client for numeric and datetime data types.
    /// (default: little-endian)
    BigEndian = 1, // bit 0 (literal 1: `1 << 0` is shift-invariant)
    /// The character set used on the client. (default: ASCII)
    CharsetEBDDIC = 1 << 1,
    /// Use VAX floating point representation. (default: IEEE 754)
    FloatVax = 1 << 2,
    /// Use ND5000 floating point representation. (default: IEEE 754)
    FloatND5000 = 1 << 3,
    /// Set is dump/load or BCP capabilities are needed by the client.
    /// (default: ON)
    BcpDumploadOff = 1 << 4,
    /// Set if the client requires warning messages on execution of the USE SQL
    /// statement. If this flag is not set, the server MUST NOT inform the
    /// client when the database changes, and therefore the client will be
    /// unaware of any accompanying collation changes. (default: ON)
    UseDbNotify = 1 << 5,
    /// Set if the change to initial database needs to succeed if the connection
    /// is to succeed. (default: OFF)
    InitDbFatal = 1 << 6,
    /// Set if the client requires warning messages on execution of a language
    /// change statement. (default: OFF)
    LangChangeWarn = 1 << 7,
}

#[bitflags]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionFlag2 {
    /// Set if the change to initial language needs to succeed if the connect is
    /// to succeed.
    InitLangFatal = 1, // bit 0 (literal 1: `1 << 0` is shift-invariant)
    /// Set if the client is the ODBC driver. This causes the server to set
    /// `ANSI_DEFAULTS=ON`, `CURSOR_CLOSE_ON_COMMIT`, `IMPLICIT_TRANSACTIONS=OFF`,
    /// `TEXTSIZE=0x7FFFFFFF` (2GB) (TDS 7.2 and earlier) `TEXTSIZE` to infinite
    /// (TDS 7.3), and `ROWCOUNT` to infinite.
    OdbcDriver = 1 << 1,
    /// (not documented)
    TransBoundary = 1 << 2,
    /// (not documented)
    CacheConnect = 1 << 3,
    /// Reserved (not really documented)
    UserTypeServer = 1 << 4,
    /// Distributed Query login
    UserTypeRemUser = 1 << 5,
    /// Replication login
    UserTypeSqlRepl = 1 << 6,
    /// Use integrated security in the client.
    IntegratedSecurity = 1 << 7,
}

#[bitflags]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionFlag3 {
    /// Request to change login's password.
    RequestChangePassword = 1, // bit 0 (literal 1: `1 << 0` is shift-invariant)
    /// XML data type instances are returned as binary XML.
    BinaryXML = 1 << 1,
    /// Client is requesting separate process to be spawned as user instance.
    SpawnUserInstance = 1 << 2,
    /// This bit is used by the server to determine if a client is able to
    /// properly handle collations introduced after TDS 7.2. TDS 7.2 and earlier
    /// clients are encouraged to use this loginpacket bit. Servers MUST ignore
    /// this bit when it is sent by TDS 7.3 or 7.4 clients.
    UnknownCollationHandling = 1 << 3,
    /// ibExtension/cbExtension fields are used.
    ExtensionUsed = 1 << 4,
}

#[bitflags]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginTypeFlag {
    /// Use T-SQL syntax.
    UseTSQL = 1, // bit 0 (literal 1: `1 << 0` is shift-invariant)
    /// Set if the client is the OLEDB driver. This causes the server to set
    /// ANSI_DEFAULTS to ON, CURSOR_CLOSE_ON_COMMIT and IMPLICIT_TRANSACTIONS to
    /// OFF, TEXTSIZE to 0x7FFFFFFF (2GB) (TDS 7.2 and earlier), TEXTSIZE to
    /// infinite (introduced in TDS 7.3), and ROWCOUNT to infinite.
    UseOLEDB = 1 << 4,
    /// This bit was introduced in TDS 7.4; however, TDS 7.1, 7.2, and 7.3
    /// clients can also use this bit in LOGIN7 to specify that the application
    /// intent of the connection is read-only. The server SHOULD ignore this bit
    /// if the highest TDS version supported by the server is lower than TDS 7.4.
    ReadOnlyIntent = 1 << 5,
}

pub(crate) const FEA_EXT_FEDAUTH: u8 = 0x02u8;
pub(crate) const FEA_EXT_TERMINATOR: u8 = 0xFFu8;
pub(crate) const FED_AUTH_LIBRARYSECURITYTOKEN: u8 = 0x01;

/// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/773a62b6-ee89-4c02-9e5e-344882630aac
#[derive(Clone, Default)]
#[cfg_attr(test, derive(PartialEq, Eq))]
struct FedAuthExt<'a> {
    fed_auth_echo: bool,
    fed_auth_token: Cow<'a, str>,
    nonce: Option<[u8; 32]>,
}

// Manual Debug so the AAD bearer token is never printed. `LoginMessage`'s own
// Debug redacts the SQL password; this keeps the federated-auth token redacted
// too (its derived Debug would otherwise leak the full token via that field).
impl std::fmt::Debug for FedAuthExt<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FedAuthExt")
            .field("fed_auth_echo", &self.fed_auth_echo)
            .field("fed_auth_token", &"<HIDDEN>")
            .field("nonce", &self.nonce.map(|_| "<present>"))
            .finish()
    }
}

/// the login packet
#[derive(Clone, Default)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct LoginMessage<'a> {
    /// the highest TDS version the client supports
    tds_version: FeatureLevel,
    /// the requested packet size
    packet_size: u32,
    /// the version of the interface library
    client_prog_ver: u32,
    /// the process id of the client application
    client_pid: u32,
    /// the connection id of the primary server
    /// (used when connecting to an "Always UP" backup server)
    connection_id: u32,
    option_flags_1: BitFlags<OptionFlag1>,
    option_flags_2: BitFlags<OptionFlag2>,
    /// flag included in option_flags_2
    integrated_security: Option<Vec<u8>>,
    type_flags: BitFlags<LoginTypeFlag>,
    option_flags_3: BitFlags<OptionFlag3>,
    client_timezone: i32,
    client_lcid: u32,
    hostname: Cow<'a, str>,
    username: Cow<'a, str>,
    password: Cow<'a, str>,
    app_name: Cow<'a, str>,
    server_name: Cow<'a, str>,
    /// the default database to connect to
    db_name: Cow<'a, str>,
    fed_auth_ext: Option<FedAuthExt<'a>>,
}

// Manual Debug so the plaintext `password` is never printed (every other
// credential-bearing type in the crate redacts it the same way).
impl std::fmt::Debug for LoginMessage<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginMessage")
            .field("tds_version", &self.tds_version)
            .field("packet_size", &self.packet_size)
            .field("client_prog_ver", &self.client_prog_ver)
            .field("client_pid", &self.client_pid)
            .field("connection_id", &self.connection_id)
            .field("option_flags_1", &self.option_flags_1)
            .field("option_flags_2", &self.option_flags_2)
            .field("integrated_security", &self.integrated_security)
            .field("type_flags", &self.type_flags)
            .field("option_flags_3", &self.option_flags_3)
            .field("client_timezone", &self.client_timezone)
            .field("client_lcid", &self.client_lcid)
            .field("hostname", &self.hostname)
            .field("username", &self.username)
            .field("password", &"<HIDDEN>")
            .field("app_name", &self.app_name)
            .field("server_name", &self.server_name)
            .field("db_name", &self.db_name)
            .field("fed_auth_ext", &self.fed_auth_ext)
            .finish()
    }
}

impl<'a> LoginMessage<'a> {
    pub fn new() -> LoginMessage<'a> {
        Self {
            packet_size: 4096,
            option_flags_1: OptionFlag1::UseDbNotify | OptionFlag1::InitDbFatal,
            option_flags_2: OptionFlag2::InitLangFatal | OptionFlag2::OdbcDriver,
            option_flags_3: BitFlags::from_flag(OptionFlag3::UnknownCollationHandling),
            app_name: "tiberius".into(),
            hostname: Self::get_hostname(),
            ..Default::default()
        }
    }

    /// Best-effort local workstation id (machine hostname), used as the default
    /// login `hostname`. Returns an empty string if it cannot be determined.
    fn get_hostname() -> Cow<'static, str> {
        #[cfg(windows)]
        fn get_computer_name() -> io::Result<String> {
            extern "system" {
                // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getcomputernamew
                fn GetComputerNameW(lpBuffer: *mut u16, nSize: *mut u32) -> i32;
            }

            // MAX_COMPUTERNAME_LENGTH is 15, plus 1 for the null terminator.
            let mut buffer = [0u16; 15 + 1];
            let mut size = buffer.len() as u32;
            let result = unsafe { GetComputerNameW(buffer.as_mut_ptr(), &mut size) };
            if result == 0 {
                let lerr = io::Error::last_os_error();
                tracing::error!("GetComputerNameW failed: {lerr}");
                Err(lerr)
            } else {
                Ok(String::from_utf16_lossy(&buffer[..size as usize]))
            }
        }

        #[cfg(target_family = "unix")]
        fn get_computer_name() -> io::Result<String> {
            // POSIX gethostname() may or may not null-terminate on truncation,
            // so we split on the first NUL (falling back to the whole buffer).
            let mut buffer = [0u8; 255 + 1];
            let result = unsafe {
                libc::gethostname(buffer.as_mut_ptr() as *mut _, buffer.len() as libc::size_t)
            };
            if result != 0 {
                let lerr = io::Error::last_os_error();
                tracing::error!("gethostname failed: {lerr}");
                Err(lerr)
            } else {
                match buffer.split(|b| *b == 0).next() {
                    Some(hostname) => Ok(String::from_utf8_lossy(hostname).into_owned()),
                    None => Ok(String::from_utf8_lossy(&buffer).into_owned()),
                }
            }
        }

        #[cfg(not(any(windows, target_family = "unix")))]
        fn get_computer_name() -> io::Result<String> {
            Ok(String::new())
        }

        get_computer_name().map(Cow::Owned).unwrap_or_default()
    }

    #[cfg(any(
        all(unix, any(feature = "integrated-auth-gssapi", feature = "sspi-rs")),
        windows
    ))]
    pub fn integrated_security(&mut self, bytes: Option<Vec<u8>>) {
        if bytes.is_some() {
            self.option_flags_2.insert(OptionFlag2::IntegratedSecurity);
        } else {
            self.option_flags_2.remove(OptionFlag2::IntegratedSecurity);
        }

        self.integrated_security = bytes;
    }

    pub fn app_name(&mut self, name: impl Into<Cow<'a, str>>) {
        self.app_name = name.into();
    }

    pub fn db_name(&mut self, db_name: impl Into<Cow<'a, str>>) {
        self.db_name = db_name.into();
    }

    pub fn server_name(&mut self, server_name: impl Into<Cow<'a, str>>) {
        self.server_name = server_name.into();
    }

    /// Sets the client / workstation name reported to the server.
    pub fn hostname(&mut self, hostname: impl Into<Cow<'a, str>>) {
        self.hostname = hostname.into();
    }

    pub fn user_name(&mut self, user_name: impl Into<Cow<'a, str>>) {
        self.username = user_name.into();
    }

    pub fn password(&mut self, password: impl Into<Cow<'a, str>>) {
        self.password = password.into();
    }

    pub fn aad_token(
        &mut self,
        token: impl Into<Cow<'a, str>>,
        fed_auth_echo: bool,
        nonce: Option<[u8; 32]>,
    ) {
        self.option_flags_3.insert(OptionFlag3::ExtensionUsed);

        self.fed_auth_ext = Some(FedAuthExt {
            fed_auth_echo,
            fed_auth_token: token.into(),
            nonce,
        })
    }

    pub fn readonly(&mut self, readonly: bool) {
        if readonly {
            self.type_flags.insert(LoginTypeFlag::ReadOnlyIntent);
        } else {
            self.type_flags.remove(LoginTypeFlag::ReadOnlyIntent);
        }
    }

    /// Sets the requested TDS packet size.
    pub fn packet_size(&mut self, size: u32) {
        self.packet_size = size;
    }

    /// Exact number of bytes [`Self::encode_to_vec`] will write, i.e. the final
    /// length of the LOGIN7 buffer.
    ///
    /// This is used to reserve the whole buffer up front so it never reallocates
    /// while the (obfuscated) password lives inside it — see the security note
    /// in `encode_to_vec`. The layout mirrors the writes in `encode_to_vec`
    /// exactly; if that layout changes this must change with it (the capacity
    /// assertion at the end of `encode_to_vec` guards against drift).
    fn encoded_len(&self) -> usize {
        // Fixed prefix written before any variable-length data. This equals the
        // initial `data_offset` computed in `encode_to_vec`:
        //   4 (length) + 5 * 4 (header u32s) + 4 (flag bytes) + 2 * 4 (tz + lcid)
        //     = 36 bytes of fixed header, then
        //   var_data.len() (13) * 2 * 2 offset/length table entries + 6
        //     (2 extra ClientId bytes + 4-byte cbSSPILong)
        //     = 36 + 52 + 6 = 94.
        const FIXED_OVERHEAD: usize = 94;

        // Every variable-length string is encoded as UTF-16 (2 bytes/unit).
        fn utf16_bytes(s: &str) -> usize {
            s.encode_utf16().count() * 2
        }

        let mut len = FIXED_OVERHEAD;
        len += utf16_bytes(&self.hostname);
        len += utf16_bytes(&self.username);
        len += utf16_bytes(&self.password);
        len += utf16_bytes(&self.app_name);
        len += utf16_bytes(&self.server_name);
        len += utf16_bytes(&self.db_name);

        if let Some(ref bytes) = self.integrated_security {
            len += bytes.len();
        }

        if let Some(ref ext) = self.fed_auth_ext {
            // 4 (FeatureExt data offset) + 1 (FEA_EXT_FEDAUTH) + 4 (feature ext
            // length) + 1 (options) + 4 (token length) + token bytes + nonce
            // + 1 (FEA_EXT_TERMINATOR).
            len += 15 + utf16_bytes(&ext.fed_auth_token);
            if ext.nonce.is_some() {
                len += 32;
            }
        }

        len
    }

    pub(crate) fn encode_to_vec(self) -> crate::Result<Zeroizing<Vec<u8>>> {
        // SECURITY (password zeroization): the password is written into this
        // buffer (only lightly obfuscated with a trivially reversible transform)
        // and the returned `Vec` is wrapped in `Zeroizing` so it is wiped on
        // drop. That wipe only covers the buffer's *current* heap allocation. If
        // the `Vec` were to reallocate *after* the password bytes were written
        // (e.g. because a later field such as db_name or the fed-auth token grew
        // it past its capacity), the old allocation would be freed WITHOUT being
        // zeroized, leaving a recoverable plaintext-equivalent copy of the
        // password in freed heap.
        //
        // To make that impossible we reserve the exact final size up front,
        // before writing any variable-length data, so no reallocation can occur
        // during encoding. The `assert_eq!` at the end verifies the capacity
        // never changed, so any future change that breaks this invariant fails
        // loudly instead of silently leaking a password copy.
        let mut cursor = Cursor::new(Vec::with_capacity(self.encoded_len()));
        let reserved_capacity = cursor.get_ref().capacity();

        // Space for the length
        cursor.write_u32::<LittleEndian>(0)?;

        cursor.write_u32::<LittleEndian>(self.tds_version as u32)?;
        cursor.write_u32::<LittleEndian>(self.packet_size)?;
        cursor.write_u32::<LittleEndian>(self.client_prog_ver)?;
        cursor.write_u32::<LittleEndian>(self.client_pid)?;
        cursor.write_u32::<LittleEndian>(self.connection_id)?;

        cursor.write_u8(self.option_flags_1.bits())?;
        cursor.write_u8(self.option_flags_2.bits())?;
        cursor.write_u8(self.type_flags.bits())?;
        cursor.write_u8(self.option_flags_3.bits())?;

        cursor.write_u32::<LittleEndian>(self.client_timezone as u32)?;
        cursor.write_u32::<LittleEndian>(self.client_lcid)?;

        // variable length data (OffsetLength)
        let var_data = [
            &self.hostname,
            &self.username,
            &self.password,
            &self.app_name,
            &self.server_name,
            &"".into(), // 5. ibExtension
            &"".into(), // ibCltIntName
            &"".into(), // ibLanguage
            &self.db_name,
            &"".into(), // 9. ClientId (6 bytes); this is included in var_data so we don't lack the bytes of cbSspiLong (4=2*2) and can insert it at the correct position
            &"".into(), // 10. ibSSPI
            &"".into(), // ibAtchDBFile
            &"".into(), // ibChangePassword
        ];

        let mut data_offset = cursor.position() as usize + var_data.len() * 2 * 2 + 6;
        let mut fea_ext_offset = 0;

        for (i, value) in var_data.iter().enumerate() {
            if i == 5 {
                // we might need to update the feature ext potion later
                fea_ext_offset = cursor.position();
            }

            // Client ID field: a fixed placeholder (not derived from the
            // MAC address). SQL Server does not require a real value here.
            if i == 9 {
                cursor.write_u32::<LittleEndian>(0)?;
                cursor.write_u16::<LittleEndian>(42)?;
                continue;
            }

            cursor.write_u16::<LittleEndian>(data_offset as u16)?;

            // ibSSPI
            if i == 10 {
                let length = if let Some(ref bytes) = self.integrated_security {
                    let bak = cursor.position();

                    cursor.set_position(data_offset as u64);
                    cursor.write_all(bytes)?;

                    data_offset += bytes.len();
                    cursor.set_position(bak);

                    bytes.len()
                } else {
                    0
                };

                cursor.write_u16::<LittleEndian>(length as u16)?;

                continue;
            }

            // jump into the data portion of the output
            let bak = cursor.position();
            cursor.set_position(data_offset as u64);

            for codepoint in value.encode_utf16() {
                cursor.write_u16::<LittleEndian>(codepoint)?;
            }

            let new_position = cursor.position() as usize;

            // prepare the password in MS-fashion
            if i == 2 {
                let buffer = cursor.get_mut();
                for byte in buffer.iter_mut().take(new_position).skip(data_offset) {
                    *byte = ((*byte << 4) & 0xf0 | (*byte >> 4) & 0x0f) ^ 0xA5;
                }
            }

            let length = new_position - data_offset;
            cursor.set_position(bak);
            data_offset += length;

            // microsoft being really consistent here... using byte offsets with utf16-length's
            // sounds like premature optimization
            cursor.write_u16::<LittleEndian>(length as u16 / 2)?;
        }

        // cbSSPILong
        cursor.write_u32::<LittleEndian>(0)?;

        // FeatureExt
        if let Some(fed_auth_ext) = self.fed_auth_ext {
            // update fea_ext_offset
            cursor.set_position(fea_ext_offset);
            cursor.write_u16::<LittleEndian>(data_offset as u16)?;
            cursor.write_u16::<LittleEndian>(4)?;

            cursor.set_position(data_offset as u64);
            data_offset += 4;
            cursor.write_u32::<LittleEndian>(data_offset as u32)?;

            cursor.write_u8(FEA_EXT_FEDAUTH)?;

            let mut token = Cursor::new(Vec::new());
            for codepoint in fed_auth_ext.fed_auth_token.encode_utf16() {
                token.write_u16::<LittleEndian>(codepoint)?;
            }
            let mut token = token.into_inner();

            // options (1) + TokenLength(4) + Token.length + nonce.length
            let feature_ext_length =
                1 + 4 + token.len() + if fed_auth_ext.nonce.is_some() { 32 } else { 0 };

            cursor.write_u32::<LittleEndian>(feature_ext_length as u32)?;

            let mut options: u8 = FED_AUTH_LIBRARYSECURITYTOKEN << 1;
            if fed_auth_ext.fed_auth_echo {
                options |= 1 // fFedAuthEcho
            }

            cursor.write_u8(options)?;

            cursor.write_u32::<LittleEndian>(token.len() as u32)?;
            cursor.write_all(token.as_slice())?;
            token.zeroize();

            if let Some(nonce) = fed_auth_ext.nonce {
                cursor.write_all(nonce.as_ref())?;
            }

            cursor.write_u8(FEA_EXT_TERMINATOR)?;
        }

        cursor.set_position(0);
        cursor.write_u32::<LittleEndian>(cursor.get_ref().len() as u32)?;

        // The password lived in this buffer; a reallocation here would have
        // leaked an un-zeroized copy into freed heap (see the security note
        // above). Reserving `encoded_len()` up front must have prevented any
        // growth — verify the invariant held.
        assert_eq!(
            cursor.get_ref().capacity(),
            reserved_capacity,
            "LOGIN7 encode buffer reallocated during encoding: a plaintext-equivalent \
             password copy may have been left in freed heap. `encoded_len()` under-reserved."
        );

        Ok(Zeroizing::new(cursor.into_inner()))
    }
}

impl<'a> Encode<BytesMut> for LoginMessage<'a> {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        let mut encoded = self.encode_to_vec()?;
        dst.extend_from_slice(encoded.as_slice());
        encoded.zeroize();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Decode;
    use byteorder::ReadBytesExt;
    use bytes::BytesMut;
    use std::io::Read;

    impl<'a> Decode<BytesMut> for LoginMessage<'a> {
        fn decode(src: &mut BytesMut) -> crate::Result<Self>
        where
            Self: Sized,
        {
            let mut cursor = Cursor::new(src);
            let mut ret = LoginMessage::new();

            let total_length = cursor.read_u32::<LittleEndian>()?;

            ret.tds_version = cursor
                .read_u32::<LittleEndian>()?
                .try_into()
                .expect("tds_version verification");
            ret.packet_size = cursor.read_u32::<LittleEndian>()?;
            ret.client_prog_ver = cursor.read_u32::<LittleEndian>()?;
            ret.client_pid = cursor.read_u32::<LittleEndian>()?;
            ret.connection_id = cursor.read_u32::<LittleEndian>()?;

            ret.option_flags_1 =
                BitFlags::from_bits(cursor.read_u8()?).expect("option_flags_1 verification");
            ret.option_flags_2 =
                BitFlags::from_bits(cursor.read_u8()?).expect("option_flags_2 verification");
            ret.type_flags =
                BitFlags::from_bits(cursor.read_u8()?).expect("type_flags verification");
            ret.option_flags_3 =
                BitFlags::from_bits(cursor.read_u8()?).expect("option_flags_3 verification");

            ret.client_timezone = cursor.read_u32::<LittleEndian>()? as i32;
            ret.client_lcid = cursor.read_u32::<LittleEndian>()?;

            macro_rules! read_offset_length_bytes {
                () => {{
                    let offset = cursor.read_u16::<LittleEndian>()?;
                    let length = cursor.read_u16::<LittleEndian>()?;
                    let pos = cursor.position();
                    cursor.set_position(offset as u64);

                    let mut values = vec![0u8; length as usize];
                    cursor.read_exact(&mut values)?;

                    cursor.set_position(pos);
                    values
                }};
            }

            macro_rules! read_offset_length_string {
                () => {
                    read_offset_length_string!("")
                };
                ($tag:expr) => {{
                    let offset = cursor.read_u16::<LittleEndian>()?;
                    let length = cursor.read_u16::<LittleEndian>()?;
                    let pos = cursor.position();
                    cursor.set_position(offset as u64);

                    if $tag == "password" {
                        let buffer = cursor.get_mut();
                        for byte in buffer
                            .iter_mut()
                            .skip(offset as usize)
                            .take(length as usize * 2)
                        {
                            *byte ^= 0xA5;
                            *byte = ((*byte << 4) & 0xf0 | (*byte >> 4) & 0x0f);
                        }
                    }

                    let mut values = vec![0u16; length as usize];
                    cursor.read_u16_into::<LittleEndian>(&mut values)?;
                    cursor.set_position(pos);

                    String::from_utf16(&values).expect("decode utf16")
                }};
            }

            ret.hostname = read_offset_length_string!().into();
            ret.username = read_offset_length_string!().into();
            ret.password = read_offset_length_string!("password").into();
            ret.app_name = read_offset_length_string!().into();
            ret.server_name = read_offset_length_string!().into();
            let fea_ext_offset = read_offset_length_bytes!(); // 5. ibExtension
            let fea_ext_offset = if fea_ext_offset.len() == 4 {
                u32::from_le_bytes(fea_ext_offset.try_into().unwrap())
            } else {
                0
            };
            let _ = read_offset_length_string!(); // ibCltIntName
            let _ = read_offset_length_string!(); // ibLanguage
            ret.db_name = read_offset_length_string!().into();
            // 9. ClientId (6 bytes); this is included in var_data so we don't lack the bytes of cbSspiLong (4=2*2) and can insert it at the correct position
            let _ = cursor.read_u32::<LittleEndian>()?;
            let _ = cursor.read_u16::<LittleEndian>()?;
            let is = read_offset_length_bytes!();
            ret.integrated_security = if is.is_empty() { None } else { Some(is) };
            let _ = read_offset_length_string!(); // ibAtchDBFile
            let _ = read_offset_length_string!(); // ibChangePassword
                                                  // let _ = cursor.read_u32::<LittleEndian>()?;
                                                  // cbSSPILong

            if fea_ext_offset != 0 {
                cursor.set_position((fea_ext_offset) as u64);

                assert!(ret.option_flags_3.contains(OptionFlag3::ExtensionUsed));
                loop {
                    let fe = cursor.read_u8()?;
                    if fe == FEA_EXT_TERMINATOR {
                        break;
                    } else if fe == FEA_EXT_FEDAUTH {
                        let fea_ext_len = cursor.read_u32::<LittleEndian>()?;
                        let pos = cursor.position();
                        let mut options = cursor.read_u8()?;
                        let fed_auth_echo = (options & 1) == 1;
                        options >>= 1;
                        if options != FED_AUTH_LIBRARYSECURITYTOKEN {
                            unimplemented!("unsupported FedAuthLibrary {:?}", options);
                        }
                        let token_len = cursor.read_u32::<LittleEndian>()? as usize;
                        let mut token = vec![0u16; token_len / 2];
                        cursor.read_u16_into::<LittleEndian>(&mut token)?;
                        let token = String::from_utf16(&token).expect("decode utf16");
                        let remaining = fea_ext_len - (cursor.position() - pos) as u32;
                        let nonce = if remaining == 32 {
                            let mut a = [0u8; 32];
                            cursor.read_exact(&mut a)?;
                            Some(a)
                        } else if remaining == 0 {
                            None
                        } else {
                            panic!("read feature ext fail: {}", remaining);
                        };

                        let fed_auth_ext = FedAuthExt {
                            fed_auth_echo,
                            fed_auth_token: token.into(),
                            nonce,
                        };
                        ret.fed_auth_ext = Some(fed_auth_ext);
                    } else {
                        unimplemented!("unsupported feature ext {:?}", fe);
                    }
                }
            }

            assert!(cursor.position() <= total_length as u64);

            Ok(ret)
        }
    }

    #[test]
    fn readonly_intent_sets_type_flag_bit() {
        // The TypeFlags byte is the third of the four flag bytes, which follow
        // the length + five u32 header fields:
        //   4 (length) + 5 * 4 (header) = 24, then OptionFlags1, OptionFlags2,
        //   TypeFlags at byte offset 26.
        const TYPE_FLAGS_OFFSET: usize = 26;

        let mut payload = BytesMut::new();
        let mut login = LoginMessage::new();
        login.readonly(true);
        login
            .clone()
            .encode(&mut payload)
            .expect("encode should succeed");

        assert_eq!(
            payload[TYPE_FLAGS_OFFSET] & LoginTypeFlag::ReadOnlyIntent as u8,
            LoginTypeFlag::ReadOnlyIntent as u8,
            "fReadOnlyIntent bit must be set in the encoded LOGIN7 TypeFlags byte"
        );

        // Round-trips back into the decoded message.
        let decoded = LoginMessage::decode(&mut payload).expect("decode should succeed");
        assert!(decoded.type_flags.contains(LoginTypeFlag::ReadOnlyIntent));

        // And when not requested, the bit stays clear.
        let mut payload = BytesMut::new();
        let mut login = LoginMessage::new();
        login.readonly(false);
        login.encode(&mut payload).expect("encode should succeed");
        assert_eq!(
            payload[TYPE_FLAGS_OFFSET] & LoginTypeFlag::ReadOnlyIntent as u8,
            0,
            "fReadOnlyIntent bit must be clear when read-only intent is not requested"
        );
    }

    #[test]
    fn login_message_round_trip() {
        let mut payload = BytesMut::new();
        let mut login = LoginMessage::new();
        login.db_name("fake-database-name");
        login.app_name("fake-app-name");
        login.server_name("fake-server-name");
        login.user_name("fake-user-name");
        login.password("fake-pw");
        login
            .clone()
            .encode(&mut payload)
            .expect("encode should succeed");

        let decoded = LoginMessage::decode(&mut payload).expect("decode should succeed");

        assert_eq!(login, decoded);
    }

    #[test]
    fn specify_aad_token() {
        let mut login = LoginMessage::new();
        let token = "fake-aad-token";
        let nonce = [3u8; 32];
        login.aad_token(token, true, Some(nonce));

        assert!(login.option_flags_3.contains(OptionFlag3::ExtensionUsed));
        assert_eq!(
            login.fed_auth_ext.expect("fed_auto_specified"),
            FedAuthExt {
                fed_auth_echo: true,
                fed_auth_token: token.into(),
                nonce: Some(nonce)
            }
        )
    }

    #[test]
    fn encoded_len_matches_actual_output_length() {
        // The reserved capacity must equal the bytes actually produced, so no
        // reallocation can occur while the password is in the buffer.
        let mut login = LoginMessage::new();
        login.db_name("some-database");
        login.user_name("some-user");
        login.password("hunter2");
        login.server_name("some-server");

        let expected = login.encoded_len();
        let encoded = login.encode_to_vec().expect("encode should succeed");
        assert_eq!(encoded.len(), expected);
    }

    #[test]
    fn large_fields_do_not_reallocate_encode_buffer() {
        // Fields far larger than the old fixed 512-byte capacity: with the old
        // code the Vec would reallocate after the password was written, leaking
        // an un-zeroized copy. `encode_to_vec` now asserts the capacity never
        // changed, so this both exercises and enforces the fix.
        let mut login = LoginMessage::new();
        login.user_name("u".repeat(200));
        login.password("p".repeat(400));
        login.db_name("d".repeat(400));
        login.server_name("s".repeat(200));
        login.app_name("a".repeat(200));

        let expected = login.encoded_len();
        let encoded = login.encode_to_vec().expect("encode should succeed");
        assert_eq!(encoded.len(), expected);
    }

    #[test]
    fn large_fed_auth_token_does_not_reallocate() {
        // Same invariant on the fed-auth path, whose token/nonce are written
        // after the password.
        let mut login = LoginMessage::new();
        login.password("p".repeat(300));
        login.db_name("d".repeat(300));
        login.aad_token("t".repeat(500), true, Some([7u8; 32]));

        let expected = login.encoded_len();
        let encoded = login.encode_to_vec().expect("encode should succeed");
        assert_eq!(encoded.len(), expected);
    }

    #[test]
    fn login_message_with_fed_auth_round_trip() {
        let mut payload = BytesMut::new();
        let mut login = LoginMessage::new();
        let nonce = [1u8; 32];
        login.aad_token("fake-aad-token", true, Some(nonce));
        login
            .clone()
            .encode(&mut payload)
            .expect("encode should succeed");

        let decoded = LoginMessage::decode(&mut payload).expect("decode should succeed");

        assert_eq!(login, decoded);
    }

    #[test]
    fn hostname_and_packet_size_setters_apply() {
        let mut login = LoginMessage::new();
        login.hostname("my-workstation");
        login.packet_size(8192);

        assert_eq!(login.hostname, "my-workstation");
        assert_eq!(login.packet_size, 8192);
    }

    #[cfg(any(
        all(unix, any(feature = "integrated-auth-gssapi", feature = "sspi-rs")),
        windows
    ))]
    #[test]
    fn integrated_security_setter_toggles_flag() {
        let mut login = LoginMessage::new();

        login.integrated_security(Some(vec![1, 2, 3, 4]));
        assert!(login
            .option_flags_2
            .contains(OptionFlag2::IntegratedSecurity));
        assert_eq!(
            login.integrated_security.as_deref(),
            Some(&[1, 2, 3, 4][..])
        );

        login.integrated_security(None);
        assert!(!login
            .option_flags_2
            .contains(OptionFlag2::IntegratedSecurity));
        assert!(login.integrated_security.is_none());
    }

    #[test]
    fn encode_round_trips_integrated_security_bytes() {
        let mut payload = BytesMut::new();
        let mut login = LoginMessage::new();
        // Set the field directly to exercise the ibSSPI encode branch without
        // depending on the platform-gated setter.
        login.integrated_security = Some(vec![9, 8, 7, 6, 5]);
        login
            .clone()
            .encode(&mut payload)
            .expect("encode should succeed");

        let decoded = LoginMessage::decode(&mut payload).expect("decode should succeed");
        assert_eq!(decoded.integrated_security, Some(vec![9, 8, 7, 6, 5]));
    }

    #[test]
    fn fed_auth_without_nonce_round_trips() {
        let mut payload = BytesMut::new();
        let mut login = LoginMessage::new();
        login.aad_token("fake-aad-token", true, None);
        login
            .clone()
            .encode(&mut payload)
            .expect("encode should succeed");

        let decoded = LoginMessage::decode(&mut payload).expect("decode should succeed");
        assert_eq!(login, decoded);
        assert_eq!(
            decoded.fed_auth_ext.expect("fed auth ext present").nonce,
            None
        );
    }

    #[test]
    fn debug_redacts_fed_auth_token() {
        let mut login = LoginMessage::new();
        login.aad_token("super-secret-aad-token", true, Some([9u8; 32]));

        let dbg = format!("{login:?}");
        assert!(
            !dbg.contains("super-secret-aad-token"),
            "AAD token leaked in Debug output: {dbg}"
        );
        assert!(dbg.contains("HIDDEN"));
    }
}
