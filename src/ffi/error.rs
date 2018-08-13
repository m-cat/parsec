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
        // unsafe { drop(err); }
    }

    // Set the new error.
    LAST_ERROR.with(|last| {
        *last.borrow_mut() = Some(FfiResult {
            error_code,
            description: description.as_ptr(),
        });
    });
}

// Retrieves the most recent error, clearing it in the process.
fn err_take() -> Option<FfiResult> {
    LAST_ERROR.with(|prev| prev.borrow_mut().take())
}

#[cfg(test)]
mod tests {
    // TODO: write a couple basic tests
}
