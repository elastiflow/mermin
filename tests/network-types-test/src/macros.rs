

#[macro_export]
macro_rules! read_var_buf {
    ($tc_ctx:expr, $off:expr, $buf:expr, $len:expr, $max_len:expr) => {
        let mut skip = false;
            for i in 0..16 {
                //debug!(&ctx, "quic_long_hdr.fixed_hdr.dc_id_len={}, i={}", quic_long_hdr.fixed_hdr.dc_id_len, i);
                if $len == i as u8 {
                    skip = true;
                    break;
                }
                let bytes: u8 = $tc_ctx.load($off).map_err(|_| TC_ACT_PIPE)?;
                $buf[i] = bytes;
                $off += 1;
            }
            if !skip {
                for i in 16..$max_len {
                    if $len == i as u8 {
                        break;
                    }
                    let bytes: u8 = $tc_ctx.load($off).map_err(|_| TC_ACT_PIPE)?;
                    $buf[i] = bytes;
                    $off += 1;
                }
            }
    };
}