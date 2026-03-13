use std::os::unix::io::RawFd;

/// Activate a launchd socket by name, returning the file descriptors.
///
/// On macOS, calls `launch_activate_socket` from libSystem.
/// On other platforms, returns an empty list.
#[cfg(target_os = "macos")]
pub fn activate_socket(name: &str) -> anyhow::Result<Vec<RawFd>> {
    use std::ffi::CString;
    use std::os::raw::c_int;
    use std::ptr;

    extern "C" {
        fn launch_activate_socket(
            name: *const libc::c_char,
            fds: *mut *mut c_int,
            cnt: *mut usize,
        ) -> c_int;
    }

    let c_name = CString::new(name)?;
    let mut fds_ptr: *mut c_int = ptr::null_mut();
    let mut cnt: usize = 0;

    let ret = unsafe { launch_activate_socket(c_name.as_ptr(), &mut fds_ptr, &mut cnt) };

    if ret != 0 {
        anyhow::bail!("launch_activate_socket({name:?}) failed with error code {ret}");
    }

    if fds_ptr.is_null() || cnt == 0 {
        return Ok(Vec::new());
    }

    let fds = unsafe { std::slice::from_raw_parts(fds_ptr, cnt) }
        .iter()
        .map(|&fd| fd as RawFd)
        .collect();

    // The pointer was allocated by launchd with malloc; we must free it.
    unsafe { libc::free(fds_ptr as *mut libc::c_void) };

    Ok(fds)
}

#[cfg(not(target_os = "macos"))]
pub fn activate_socket(_name: &str) -> anyhow::Result<Vec<RawFd>> {
    Ok(Vec::new())
}
