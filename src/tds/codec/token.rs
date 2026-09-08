mod token_alt_meta_data;
mod token_alt_row;
mod token_col_info;
mod token_col_metadata;
mod token_done;
mod token_env_change;
mod token_error;
mod token_feature_ext_ack;
mod token_fed_auth_info;
mod token_info;
mod token_login_ack;
mod token_order;
mod token_return_value;
mod token_row;
mod token_session_state;
mod token_sspi;
mod token_tab_name;
mod token_type;

pub use token_alt_meta_data::*;
pub use token_alt_row::*;
pub use token_col_info::*;
pub use token_col_metadata::*;
pub use token_done::*;
pub use token_env_change::*;
pub use token_error::*;
pub use token_feature_ext_ack::*;
pub use token_fed_auth_info::*;
pub use token_info::*;
pub use token_login_ack::*;
pub use token_order::*;
pub use token_return_value::*;
pub use token_row::*;
pub use token_session_state::*;
pub use token_sspi::*;
pub use token_tab_name::*;
pub use token_type::*;

/// Upper bound on the length a variable-length token declares for its body
/// before we allocate for it. The length is server-controlled; without a cap a
/// single 4-byte field could force a multi-gigabyte allocation. Chosen well
/// above any realistic FEDAUTHINFO / SESSIONSTATE payload.
pub(crate) const MAX_TOKEN_BODY: usize = 16 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_token_body_is_sixteen_mebibytes() {
        // 16 MiB. Guards the `16 * 1024 * 1024` computation against arithmetic
        // mutation (e.g. `+`/`/` would yield a wildly different cap).
        assert_eq!(MAX_TOKEN_BODY, 16_777_216);
    }
}
