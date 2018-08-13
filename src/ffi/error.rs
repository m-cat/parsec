// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use ffi_utils::FfiResult;
use std::cell::RefCell;
use std::ffi::CString;
use std::ptr;

thread_local!{
    static LAST_ERROR: RefCell<Option<FfiResult>> = RefCell::new(None);
}

/// Returns a pointer to the last error that occurred. This pointer will become invalid the next
/// time an error occurs, so make sure to copy any needed data. This may return NULL if no error has
/// occurred.
#[no_mangle]
pub unsafe extern "C" fn err_last() -> *const FfiResult {
    LAST_ERROR.with(|last| match *last.borrow() {
        Some(err) => &err,
        None => ptr::null(),
    })
}

/// Clears the last error.
#[no_mangle]
pub unsafe extern "C" fn err_clear() {
    LAST_ERROR.with(|last| {
        *last.borrow_mut() = None;
    });
}

/// Sets the error. For internal use.
pub(crate) fn err_set(error_code: i32, description: CString) {
    // Clear the last error.
    if let Some(err) = err_take() {
        // Drop the allocated data.
        let _ = unsafe { CString::from_raw(err.description as *mut _) };
    }

    // Set the new error.
    LAST_ERROR.with(|last| {
        *last.borrow_mut() = Some(FfiResult {
            error_code,
            description: description.into_raw(),
        });
    });
}

// Retrieves the most recent error, clearing it in the process.
fn err_take() -> Option<FfiResult> {
    LAST_ERROR.with(|prev| prev.borrow_mut().take())
}

#[cfg(test)]
mod tests {
    use error;
    use ffi::*;
    use std::ffi::CStr;

    #[test]
    fn ffi_error_api() {
        utils::memory_check("ffi_error", 100, || {
            let bytes = &[192];

            unsafe {
                // No error has occurred yet, should be null.
                assert!(err_last().is_null());

                // Generate and get the last error code.
                let err_code = match utils::get_1(|out| {
                    public_id_from_bytes(bytes.as_ptr(), bytes.len(), out)
                }) {
                    Ok(_) => panic!("Expected error code."),
                    Err(e) => e,
                };
                assert_eq!(err_code, error::codes::ERR_UTF8);

                // Get the last full error.
                let err = err_last();
                assert_eq!((*err).error_code, err_code);
                assert_eq!(
                    unwrap!(CStr::from_ptr((*err).description).to_str()),
                    "Utf8 error: Utf8Error { valid_up_to: 0, error_len: Some(1) }"
                );

                // Ensure the last error did not get cleared.
                assert!(!err_last().is_null());

                // Generate and get another error code.
                let err_code = match utils::get_1(|out| {
                    public_id_from_bytes(bytes.as_ptr(), bytes.len(), out)
                }) {
                    Ok(_) => panic!("Expected error code."),
                    Err(e) => e,
                };
                assert_eq!(err_code, error::codes::ERR_UTF8);

                // Clear the error.
                err_clear();

                // Ensure the last error got cleared.
                assert!(err_last().is_null());
            }
        })
    }
}
