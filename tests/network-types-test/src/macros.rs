

#[macro_export]
macro_rules! read_var_buf {
    ($tc_ctx:expr, $off:expr, $buf:expr, $len:expr, $max_len:expr) => {
        let mut skip = false;
            for i in 0..16 {
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
    /*
            // TODO: CHECK FOR OPTIMIZATION POTENTIAL
            if (ctx.len() - off as u32) < QUIC_MAX_CID_LEN as u32 {
                let mut idx = 0;
                'outer: for _i in 0..5 {
                    for _j in 0..4 {
                        let bytes: u8 = ctx.load(off).map_err(|_| TC_ACT_PIPE)?;
                        quic_long_hdr.dc_id[idx] = bytes;
                        idx += 1;
                        if quic_long_hdr.fixed_hdr.dc_id_len == idx as u8 {
                            break 'outer;
                        }
                        off += 1;
                    }
                }
            }
  */
}