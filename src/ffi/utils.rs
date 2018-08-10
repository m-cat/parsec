// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Utils.

use error::Error;
use ffi::error;
use std::fmt::Debug;
use std::panic::{self, AssertUnwindSafe};
use std::slice;

#[macro_export]
macro_rules! assert_ffi {
    ($e:expr) => {{
        let err_code: i32 = $e;
        if err_code != 0 {
            use std::ffi::CStr;
            use $crate::ffi::err_last;
            let err = err_last();
            let err_desc = unwrap!(CStr::from_ptr((*err).description).to_str());
            panic!("Error with code {}: {}", err_code, err_desc)
        }
    }};
}

fn catch_unwind_result<'a, F, T, E>(f: F) -> Result<T, E>
where
    F: FnOnce() -> Result<T, E>,
    E: Debug + From<&'a str>,
{
    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Err(_) => Err(E::from("panic")),
        Ok(result) => result,
    }
}

/// Catches panics. On error sets the thread-local error message and returns the `i32` error code.
pub fn catch_unwind_err_set<'a, F>(f: F) -> i32
where
    F: FnOnce() -> Result<(), Error>,
{
    match catch_unwind_result(f) {
        Err(err) => {
            let (error_code, description) = ffi_result!(Err::<(), Error>(err));
            error::err_set(error_code, description);
            error_code
        }
        Ok(()) => 0,
    }
}

/// Runs an FFI function that contains zero output parameters and returns an `i32` error code on
/// failure.
pub unsafe fn get_0<F>(f: F) -> Result<(), i32>
where
    F: FnOnce() -> i32,
{
    let res = f();

    if res == 0 {
        Ok(())
    } else {
        Err(res)
    }
}

/// Runs an FFI function that contains one output parameter and returns either the output parameter
/// on success or an `i32` error code on failure.
pub unsafe fn get_1<F, T>(f: F) -> Result<T, i32>
where
    F: FnOnce(*mut T) -> i32,
{
    use std::mem;

    let mut output: T = mem::uninitialized();
    let res = f(&mut output);

    if res == 0 {
        Ok(output)
    } else {
        Err(res)
    }
}

/// Runs an FFI function that contains a u8 array and length output parameters and returns either
/// the array and length output parameters on success or an `i32` error code on failure.
pub unsafe fn get_vec_u8<F>(f: F) -> Result<Vec<u8>, i32>
where
    F: FnOnce(*mut *const u8, *mut usize) -> i32,
{
    use std::mem;

    let mut ptr: *const u8 = mem::uninitialized();
    let mut len: usize = mem::uninitialized();
    let res = f(&mut ptr, &mut len);

    if res == 0 {
        Ok(slice::from_raw_parts(ptr, len).to_vec())
    } else {
        Err(res)
    }
}

#[cfg(test)]
pub(crate) fn memory_check<F>(test: &str, num_iterations: usize, f: F)
where
    F: FnOnce() + Copy,
{
    #[cfg(target_os = "linux")]
    use procinfo;

    // Measure the amount of baseline memory.
    #[cfg(target_os = "linux")]
    let memory_before = {
        let memory_before = procinfo::pid::statm_self().unwrap().resident;
        memory_before
    };

    #[cfg(not(target_os = "linux"))]
    println!("[{}] Linux required, skipping memory check.\n", test);

    for _ in 1..num_iterations {
        f();
    }

    // Measure the amount of memory in use at the end.
    #[cfg(target_os = "linux")]
    {
        let memory_after = procinfo::pid::statm_self().unwrap().resident;
        println!(
            "\n[{}] Memory before: {}, memory after: {}",
            test, memory_before, memory_after
        );
        if memory_before < memory_after {
            println!(
                "[{}] Warning: memory grew during the execution of this test. This is expected \
                 if running sanitizers, otherwise there is probably a leak.",
                test
            );
        }
    }
}
