/// Reads a variable-length buffer from a TC context with a maximum length of 32 bytes.
///
/// This macro reads up to `$max_len` bytes from the given TC context `$tc_ctx`
/// starting at offset `$off`. The actual number of bytes read is determined by `$len`.
///
/// The `$max_len` is capped at 32 bytes due to limitations in the eBPF verifier,
/// which restricts the complexity of loops in kernel space to ensure termination.
/// This macro will fail to compile if `$max_len` is greater than 32.
///
/// # Arguments
/// * `$tc_ctx`: The traffic control context to read from.
/// * `$off`: A mutable variable holding the current offset, which will be advanced.
/// * `$buf`: The destination buffer to write the bytes into.
/// * `$len`: The number of bytes to read.
/// * `$max_len`: The maximum number of bytes to read, cannot exceed 32.
///
/// # Returns
/// `Ok(())` on success. On failure to load a byte from the context,
/// it returns an `Err` with a TC action code, likely `TC_ACT_PIPE`.
#[macro_export]
macro_rules! read_var_buf_32 {
    ($tc_ctx:expr, $off:ident, $buf:expr, $len:expr, $max_len:expr) => {
        (|| -> Result<(), i32> {
            // This will cause a compile-time error if $max_len is greater than 32.
            const _: () = assert!($max_len <= 32, "$max_len cannot be greater than 32");
            for i in 0..core::cmp::min(16, $max_len) {
                if i as u8 >= $len {
                    return Ok(());
                }
                let byte: u8 = $tc_ctx.load($off).map_err(|_| TC_ACT_PIPE)?;
                $buf[i] = byte;
                $off += 1;
            }
            if $max_len > 16 {
                for i in 16..$max_len {
                    if i as u8 >= $len {
                        return Ok(());
                    }
                    let byte: u8 = $tc_ctx.load($off).map_err(|_| TC_ACT_PIPE)?;
                    $buf[i] = byte;
                    $off += 1;
                }
            }
            Ok(())
        })()
    };
}