uint_enum! {
    /// Types of tokens in a token stream. Read from the first byte of the stream.
    pub enum TokenType {
        /// Used to send the status value of an RPC to the client. The server
        /// also uses this token to send the result status value of a stored
        /// procedure executed through SQL Batch.
        ///
        /// This token MUST be returned to the client when an RPC is executed by
        /// the server.
        ReturnStatus = 0x79,

        /// Describes the data type, length, and name of column data that
        /// result from a COMPUTE clause (`ALTMETADATA`). This token describes
        /// the format of the following `ALTROW` data streams.
        AltMetaData = 0x88,

        /// Describes the result set for interpretation of following ROW data
        /// streams
        ColMetaData = 0x81,

        /// Used to send an error message to the client.
        Error = 0xAA,

        /// Used to send an information message to the client.
        Info = 0xAB,

        /// Used to inform the client by which columns the data is ordered.
        Order = 0xA9,

        /// Describes the column information in browse mode.
        ColInfo = 0xA5,

        /// Used to send the table name to the client in browse mode (for
        /// example `SELECT ... FOR BROWSE`). Paired with the COLINFO token,
        /// whose entries reference the tables carried here by index.
        TabName = 0xA4,

        /// Used to send the return value of an RPC to the client. When an RPC is
        /// executed, the associated parameters may be defined as input or
        /// output (or "return") parameters.
        ///
        /// This token is used to send a description of the return parameter to
        /// the client. This token is also used to describe the value returned
        /// by a user-defined function (UDF) when executed as an RPC.
        ReturnValue = 0xAC,

        /// Used to send a response to a login request to the client.
        LoginAck = 0xAD,

        /// Used to send a complete row, as defined by the COLNAME and COLFMT
        /// tokens, to the client.
        Row = 0xD1,

        /// Used to send a row with null bitmap compression, as defined by the
        /// COLMETADATA token.
        NbcRow = 0xD2,

        /// Used to send a complete row of computed data, as defined by the
        /// `ALTMETADATA` token, to the client. This is the row produced by a
        /// COMPUTE or COMPUTE BY clause.
        AltRow = 0xD3,

        /// The SSPI token returned during the login process.
        Sspi = 0xED,

        /// Used to inform the client about the current session state so the
        /// session can be transparently recovered after a broken connection
        /// (connection resiliency). Sent only when session recovery is enabled.
        SessionState = 0xE4,

        /// Carries the information the client needs to acquire a federated
        /// authentication (Azure Active Directory) access token, such as the
        /// Security Token Service URL and the Service Principal Name. Sent by
        /// the server during a library-driven federated authentication flow.
        FedAuthInfo = 0xEE,

        /// A notification of an environment change (such as database and
        /// language).
        EnvChange = 0xE3,

        /// Indicates the completion status of a SQL statement.
        ///
        /// This token is used to indicate the completion of a SQL statement.
        /// Because multiple SQL statements may be sent to the server in a
        /// single SQL batch, multiple DONE tokens may be generated. In this
        /// case, all but the final DONE token will have a Status value with the
        /// DONE_MORE bit set.
        ///
        /// A DONE token is returned for each SQL statement in the SQL batch,
        /// except for variable declarations.
        ///
        /// For execution of SQL statements within stored procedures, DONEPROC
        /// and DONEINPROC tokens are used in place of DONE tokens.
        Done = 0xFD,

        /// Indicates the completion status of a stored procedure. This is also
        /// generated for stored procedures executed through SQL statements.
        DoneProc = 0xFE,

        /// Indicates the completion status of a SQL statement within a stored procedure.
        DoneInProc = 0xFF,

        /// used to send an optional acknowledge message to the client for features that
        /// are defined in FeatureExt. The token stream is sent only along with the LOGINACK
        /// in a Login Response message.
        FeatureExtAck = 0xAE,
    }
}

#[cfg(test)]
mod tests {
    use super::TokenType;
    use std::convert::TryFrom;

    #[test]
    fn known_values_map_to_variants() {
        let cases: &[(u8, TokenType)] = &[
            (0x79, TokenType::ReturnStatus),
            (0x88, TokenType::AltMetaData),
            (0x81, TokenType::ColMetaData),
            (0xAA, TokenType::Error),
            (0xAB, TokenType::Info),
            (0xA9, TokenType::Order),
            (0xA5, TokenType::ColInfo),
            (0xA4, TokenType::TabName),
            (0xAC, TokenType::ReturnValue),
            (0xAD, TokenType::LoginAck),
            (0xD1, TokenType::Row),
            (0xD2, TokenType::NbcRow),
            (0xD3, TokenType::AltRow),
            (0xED, TokenType::Sspi),
            (0xE4, TokenType::SessionState),
            (0xEE, TokenType::FedAuthInfo),
            (0xE3, TokenType::EnvChange),
            (0xFD, TokenType::Done),
            (0xFE, TokenType::DoneProc),
            (0xFF, TokenType::DoneInProc),
            (0xAE, TokenType::FeatureExtAck),
        ];

        for &(byte, variant) in cases {
            // Byte -> variant.
            assert_eq!(TokenType::try_from(byte).unwrap(), variant);
            // Round-trip: variant -> byte -> variant.
            assert_eq!(variant as u8, byte);
            assert_eq!(TokenType::try_from(variant as u8).unwrap(), variant);
        }
    }

    #[test]
    fn unknown_byte_is_rejected() {
        // 0x00 is not a defined token type.
        assert!(TokenType::try_from(0x00u8).is_err());
    }
}
