//! Windows authentication through SSPI's `Negotiate` package, as ODBC and ADO.NET log in:
//! Kerberos when the server's SPN (`MSSQLSvc/host:port`) is registered in the domain, NTLM
//! otherwise. Used for both the current Windows identity (`AuthMethod::Integrated`) and a named
//! account (`AuthMethod::Windows`).
//!
//! Kerberos finishes in fewer legs than NTLM (with mutual authentication the server answers the
//! first token once and nothing is sent back), so the login keeps exchanging tokens until SSPI
//! says the context is complete, rather than assuming NTLM's three messages.

use std::{ffi::c_void, io, ptr};
use windows_sys::Win32::Foundation::{
    SEC_E_OK, SEC_I_COMPLETE_AND_CONTINUE, SEC_I_COMPLETE_NEEDED, SEC_I_CONTINUE_NEEDED,
};
use windows_sys::Win32::Security::Authentication::Identity::{
    AcquireCredentialsHandleW, CompleteAuthToken, DeleteSecurityContext, FreeContextBuffer,
    FreeCredentialsHandle, InitializeSecurityContextW, SecBuffer, SecBufferDesc,
    ISC_REQ_ALLOCATE_MEMORY, ISC_REQ_CONFIDENTIALITY, ISC_REQ_FLAGS, ISC_REQ_INTEGRITY,
    ISC_REQ_MUTUAL_AUTH, ISC_REQ_REPLAY_DETECT, ISC_REQ_SEQUENCE_DETECT, SECBUFFER_TOKEN,
    SECBUFFER_VERSION, SECPKG_CRED_OUTBOUND, SECURITY_NATIVE_DREP,
};
use windows_sys::Win32::Security::Credentials::SecHandle;
use windows_sys::Win32::System::Rpc::{SEC_WINNT_AUTH_IDENTITY_UNICODE, SEC_WINNT_AUTH_IDENTITY_W};
use zeroize::Zeroizing;

const REQUIREMENTS: ISC_REQ_FLAGS = ISC_REQ_MUTUAL_AUTH
    | ISC_REQ_CONFIDENTIALITY
    | ISC_REQ_INTEGRITY
    | ISC_REQ_REPLAY_DETECT
    | ISC_REQ_SEQUENCE_DETECT
    | ISC_REQ_ALLOCATE_MEMORY;

/// A named account's credentials, for `Negotiate::new`.
pub(crate) struct Account<'a> {
    pub(crate) user: &'a str,
    pub(crate) domain: Option<&'a str>,
    pub(crate) password: &'a str,
}

/// One client-side SSPI `Negotiate` context.
pub(crate) struct Negotiate {
    credentials: SecHandle,
    context: Option<SecHandle>,
    target: Vec<u16>,
}

/// What one step of the exchange produced.
pub(crate) struct Step {
    /// The token to send to the server (may be empty).
    pub(crate) token: Vec<u8>,
    /// Whether the context is complete: nothing more is expected from the server.
    pub(crate) done: bool,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

impl Negotiate {
    /// Credentials for the identity this process runs as (`None`), or for `account`, to
    /// authenticate to the service `spn`.
    pub(crate) fn new(spn: &str, account: Option<Account<'_>>) -> io::Result<Self> {
        let package = wide("Negotiate");
        let mut credentials = SecHandle::default();
        // The identity's buffers must live until AcquireCredentialsHandleW returns; the password
        // is wiped when they drop.
        let mut user;
        let mut domain;
        let mut password;
        let identity = match account {
            Some(account) => {
                user = account.user.encode_utf16().collect::<Vec<u16>>();
                domain = account
                    .domain
                    .unwrap_or("")
                    .encode_utf16()
                    .collect::<Vec<u16>>();
                password = Zeroizing::new(account.password.encode_utf16().collect::<Vec<u16>>());
                Some(SEC_WINNT_AUTH_IDENTITY_W {
                    User: user.as_mut_ptr(),
                    UserLength: user.len() as u32,
                    Domain: domain.as_mut_ptr(),
                    DomainLength: domain.len() as u32,
                    Password: password.as_mut_ptr(),
                    PasswordLength: password.len() as u32,
                    Flags: SEC_WINNT_AUTH_IDENTITY_UNICODE,
                })
            }
            None => None,
        };
        let auth_data = identity.as_ref().map_or(ptr::null(), |i| {
            i as *const SEC_WINNT_AUTH_IDENTITY_W as *const c_void
        });
        // SAFETY: every pointer is valid for the call (the package name and the identity's
        // buffers outlive it); `credentials` is written on success only.
        let status = unsafe {
            AcquireCredentialsHandleW(
                ptr::null(),
                package.as_ptr(),
                SECPKG_CRED_OUTBOUND,
                ptr::null(),
                auth_data,
                None,
                ptr::null(),
                &mut credentials,
                ptr::null_mut(),
            )
        };
        if status != SEC_E_OK {
            return Err(io::Error::from_raw_os_error(status));
        }
        Ok(Self {
            credentials,
            context: None,
            target: wide(spn),
        })
    }

    /// The next token: the first with `None`, then one for each token the server sent.
    pub(crate) fn step(&mut self, input: Option<&[u8]>) -> io::Result<Step> {
        let mut input_buffer = SecBuffer {
            cbBuffer: input.map_or(0, |i| i.len() as u32),
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: input.map_or(ptr::null_mut(), |i| i.as_ptr() as *mut c_void),
        };
        let input_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut input_buffer,
        };
        let mut output_buffer = SecBuffer {
            cbBuffer: 0,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: ptr::null_mut(),
        };
        let mut output_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut output_buffer,
        };
        let mut context = self.context.unwrap_or_default();
        let mut attributes = 0u32;
        // SAFETY: the handles are ours and live; the input buffer borrows `input` for the call;
        // the output buffer is allocated by SSPI (ISC_REQ_ALLOCATE_MEMORY) and freed below.
        let status = unsafe {
            InitializeSecurityContextW(
                &self.credentials,
                self.context
                    .as_ref()
                    .map_or(ptr::null(), |c| c as *const SecHandle),
                self.target.as_ptr(),
                REQUIREMENTS,
                0,
                SECURITY_NATIVE_DREP,
                if input.is_some() {
                    &input_desc
                } else {
                    ptr::null()
                },
                0,
                &mut context,
                &mut output_desc,
                &mut attributes,
                ptr::null_mut(),
            )
        };
        let token = if output_buffer.pvBuffer.is_null() {
            Vec::new()
        } else {
            // SAFETY: SSPI wrote `cbBuffer` bytes at `pvBuffer`, which we free once copied.
            let token = unsafe {
                std::slice::from_raw_parts(
                    output_buffer.pvBuffer as *const u8,
                    output_buffer.cbBuffer as usize,
                )
            }
            .to_vec();
            unsafe { FreeContextBuffer(output_buffer.pvBuffer) };
            token
        };
        match status {
            SEC_E_OK
            | SEC_I_CONTINUE_NEEDED
            | SEC_I_COMPLETE_NEEDED
            | SEC_I_COMPLETE_AND_CONTINUE => {}
            error => return Err(io::Error::from_raw_os_error(error)),
        }
        self.context = Some(context);
        if status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE {
            // SAFETY: the context was just made; the descriptor is the step's own output.
            let completed = unsafe { CompleteAuthToken(&context, &output_desc) };
            if completed != SEC_E_OK {
                return Err(io::Error::from_raw_os_error(completed));
            }
        }
        Ok(Step {
            token,
            done: status == SEC_E_OK || status == SEC_I_COMPLETE_NEEDED,
        })
    }
}

impl Drop for Negotiate {
    fn drop(&mut self) {
        // SAFETY: both handles were made by SSPI and are released once.
        unsafe {
            if let Some(context) = &self.context {
                DeleteSecurityContext(context);
            }
            FreeCredentialsHandle(&self.credentials);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The current identity's first Negotiate token: SPNEGO when Kerberos could be tried
    /// (ASN.1, 0x60), or a raw NTLM NEGOTIATE message ("NTLMSSP\0") where Negotiate went
    /// straight to NTLM (a workgroup machine, as CI's runner).
    #[test]
    fn the_first_token_is_spnego_or_ntlm() {
        let mut negotiate = Negotiate::new("MSSQLSvc/localhost:1433", None).unwrap();
        let step = negotiate.step(None).unwrap();
        assert!(!step.done, "a first token never completes the exchange");
        assert!(
            step.token.first() == Some(&0x60) || step.token.starts_with(b"NTLMSSP\0"),
            "{:02x?}",
            &step.token[..step.token.len().min(16)]
        );
    }

    /// A named account's credentials are taken without contacting anyone: a wrong password
    /// shows only when the server judges the exchange.
    #[test]
    fn a_named_account_s_credentials_are_acquired() {
        let account = Account {
            user: "nobody",
            domain: Some("NOWHERE"),
            password: "not-checked-here",
        };
        let mut negotiate = Negotiate::new("MSSQLSvc/localhost:1433", Some(account)).unwrap();
        assert!(!negotiate.step(None).unwrap().token.is_empty());
    }
}
