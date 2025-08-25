#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    OutOfBounds,
    MalformedHeader,
    Unsupported,
}
/// Reads a variable-length buffer from a TC context with a maximum length of 32 bytes.
///
/// This macro reads up to 32 bytes from the given TC context `$tc_ctx`
/// starting at offset `$off`. The actual number of bytes read is determined by `$len`.
///
/// The implementation uses two bounded for loops to comply with eBPF verifier requirements:
/// 1. The first loop handles up to 16 iterations (the maximum loop depth allowed by the eBPF verifier)
/// 2. A second loop handles any remaining iterations up to 32 total iterations
///
/// # Arguments
/// * `$tc_ctx`: The traffic control context to read from.
/// * `$off`: A mutable variable holding the current offset, which will be advanced.
/// * `$buf`: The destination buffer to write the bytes into.
/// * `$len`: The number of bytes to read.
/// * `$chunk`: The number of bytes to read at a time using `load_bytes`.
///
/// # Returns
/// `Ok(bytes_read)` on success, where `bytes_read` is the number of bytes actually read.
/// On failure to load bytes from the context returns an `Err`.
#[macro_export]
macro_rules! read_var_buf {
    ($tc_ctx:expr, $off:ident, $buf:expr, $len:expr, $chunk:expr) => {
        (|| -> Result<usize, ()> {
            let mut bytes_read_total = 0;
            // Use a for loop with a fixed bound to read multiple chunks
            for _ in 0..16 {
                if bytes_read_total >= $len {
                    break;
                }
                let bytes_to_read = core::cmp::min($len - bytes_read_total, $chunk);
                let bytes_read = $tc_ctx
                    .load_bytes(
                        $off,
                        &mut $buf[bytes_read_total..bytes_read_total + bytes_to_read],
                    )
                    .map_err(|_| ())?;
                if bytes_read == 0 {
                    break;
                }
                $off += bytes_read;
                bytes_read_total += bytes_read;
            }

            // Second loop: handle remaining iterations if max_len > 16
            for _ in 0..16 {
                if bytes_read_total >= $len {
                    break;
                }
                let bytes_to_read = core::cmp::min($len - bytes_read_total, $chunk);
                let bytes_read = $tc_ctx
                    .load_bytes(
                        $off,
                        &mut $buf[bytes_read_total..bytes_read_total + bytes_to_read],
                    )
                    .map_err(|_| ())?;
                if bytes_read == 0 {
                    break;
                }
                $off += bytes_read;
                bytes_read_total += bytes_read;
            }

            Ok(bytes_read_total)
        })()
    };
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec::Vec;

    // TcContext implementation that matches the interface of host_test_shim::TcContext
    pub struct TcContext {
        data: Vec<u8>,
    }
    impl TcContext {
        pub fn new(data: Vec<u8>) -> Self {
            Self { data }
        }

        // This is needed by the read_var_buf_32 macro
        fn load_bytes(&self, offset: usize, buf: &mut [u8]) -> Result<usize, ()> {
            if offset >= self.data.len() {
                return Ok(0);
            }

            let available = self.data.len() - offset;
            let to_copy = core::cmp::min(available, buf.len());

            buf[..to_copy].copy_from_slice(&self.data[offset..offset + to_copy]);
            Ok(to_copy)
        }
    }

    #[test]
    fn test_read_var_buf_chunk_4() {
        // Create test data
        let mut test_data = [0u8; 32];
        for i in 0..32 {
            test_data[i] = i as u8;
        }
        let ctx = TcContext::new(test_data.to_vec());

        // Test reading with chunk size 4
        let mut buf = [0u8; 32];
        let mut offset = 0;
        let len = 32;
        let chunk = 4;

        let result = crate::read_var_buf!(ctx, offset, buf, len, chunk);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 32); // Should return the number of bytes read

        // Verify the data was read correctly
        assert_eq!(offset, 32); // Offset should be advanced by 32
        assert_eq!(buf, test_data); // Buffer should contain the test data
    }

    #[test]
    fn test_read_var_buf_chunk_8() {
        // Create test data
        let mut test_data = [0u8; 32];
        for i in 0..32 {
            test_data[i] = i as u8;
        }
        let ctx = TcContext::new(test_data.to_vec());

        // Test reading with chunk size 8
        let mut buf = [0u8; 32];
        let mut offset = 0;
        let len = 32;
        let chunk = 8;

        let result = crate::read_var_buf!(ctx, offset, buf, len, chunk);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 32); // Should return the number of bytes read

        // Verify the data was read correctly
        assert_eq!(offset, 32); // Offset should be advanced by 32
        assert_eq!(buf, test_data); // Buffer should contain the test data
    }

    #[test]
    fn test_read_var_buf_chunk_16() {
        // Create test data
        let mut test_data = [0u8; 32];
        for i in 0..32 {
            test_data[i] = i as u8;
        }
        let ctx = TcContext::new(test_data.to_vec());

        // Test reading with chunk size 16
        let mut buf = [0u8; 32];
        let mut offset = 0;
        let len = 32;
        let chunk = 16;

        let result = crate::read_var_buf!(ctx, offset, buf, len, chunk);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 32); // Should return the number of bytes read

        // Verify the data was read correctly
        assert_eq!(offset, 32); // Offset should be advanced by 32
        assert_eq!(buf, test_data); // Buffer should contain the test data
    }

    #[test]
    fn test_read_var_buf_partial_read() {
        // Create test data
        let mut test_data = [0u8; 32];
        for i in 0..32 {
            test_data[i] = i as u8;
        }
        let ctx = TcContext::new(test_data.to_vec());

        // Test reading only part of the data
        let mut buf = [0u8; 32];
        let mut offset = 0;
        let len = 16; // Only read 16 bytes
        let chunk = 4;

        let result = crate::read_var_buf!(ctx, offset, buf, len, chunk);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 16); // Should return the number of bytes read

        // Verify the data was read correctly
        assert_eq!(offset, 16); // Offset should be advanced by 16
        for i in 0..16 {
            assert_eq!(buf[i], test_data[i]); // Buffer should contain the first 16 bytes of test data
        }
    }

    #[test]
    fn test_read_var_buf_large() {
        // Create empty test data
        let mut test_data = [0u8; 48];
        for i in 0..48 {
            test_data[i] = i as u8;
        }
        let ctx = TcContext::new(test_data.to_vec());

        // Test reading from empty context
        let mut buf = [0u8; 48];
        let mut offset = 0;
        let len = 48;
        let chunk = 16;

        let result = crate::read_var_buf!(ctx, offset, buf, len, chunk);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 48); // Should return the number of bytes read

        // Verify we read 48 byes
        assert_eq!(offset, 48); // Offset should advanced by 48
        for i in 0..48 {
            assert_eq!(buf[i], test_data[i]); // Buffer should contain the test data
        }
    }

    #[test]
    fn test_read_var_buf_uneven() {
        // Create empty test data
        let mut test_data = [0u8; 48];
        for i in 0..48 {
            test_data[i] = i as u8;
        }
        let ctx = TcContext::new(test_data.to_vec());

        // Test reading from empty context
        let mut buf = [0u8; 48];
        let mut offset = 0;
        let len = 42;
        let chunk = 10;

        let result = crate::read_var_buf!(ctx, offset, buf, len, chunk);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42); // Should return the number of bytes read

        // Verify we read 48 byes
        assert_eq!(offset, 42); // Offset should advanced by 42
        for i in 0..42 {
            assert_eq!(buf[i], test_data[i]); // Buffer should contain the test data
        }
    }

    #[test]
    fn test_read_var_buf_len_too_long() {
        // Create empty test data
        let mut test_data = [0u8; 80];
        for i in 0..80 {
            test_data[i] = i as u8;
        }
        let ctx = TcContext::new(test_data.to_vec());

        // Test reading from empty context
        let mut buf = [0u8; 80];
        let mut offset = 0;
        let len = 80;
        let chunk = 2;

        let result = crate::read_var_buf!(ctx, offset, buf, len, chunk);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 64); // Should return the number of bytes read

        // Verify we read 64 bytes
        assert_eq!(offset, 64); // Offset should advanced by 64
        for i in 0..64 {
            assert_eq!(buf[i], test_data[i]); // Buffer should contain the test data
        }
    }
}
