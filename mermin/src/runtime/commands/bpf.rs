//! BPF diagnostic command
//!
//! Tests eBPF program loading, filesystem writeability, and attach/detach operations.
//! This command verifies that the system is properly configured for running Mermin's
//! eBPF-based network monitoring.

use aya::{
    programs::{
        LinkOrder, SchedClassifier, TcAttachType,
        links::PinnedLink,
        tc::{NlOptions, SchedClassifierLinkId, TcAttachOptions},
    },
    util::KernelVersion,
};
use pnet::datalink;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{
    EnvFilter,
    fmt::{Layer, format::FmtSpan},
    prelude::__tracing_subscriber_SubscriberExt,
    util::SubscriberInitExt,
};

use crate::{
    error::{MerminError, Result},
    iface::controller::IfaceController,
    runtime::capabilities,
};

/// Result of testing a single interface
struct InterfaceTestResult {
    interface: String,
    bpf_fs_writable: bool,
    attach_success: bool,
    pin_success: Option<bool>,
    detach_success: bool,
}

impl InterfaceTestResult {
    fn overall_status(&self) -> bool {
        self.attach_success && self.detach_success
    }
}

fn matches_skip_pattern(name: &str, skip_patterns: &[String]) -> bool {
    skip_patterns
        .iter()
        .any(|pattern| IfaceController::glob_matches(pattern, name))
}

/// Execute the BPF diagnostic command
pub async fn execute(interface: Option<&str>, pattern: &[String], skip: &[String]) -> Result<()> {
    let log_level = std::env::var("MERMIN_LOG_LEVEL")
        .unwrap_or_else(|_| "info".to_string())
        .parse::<tracing::Level>()
        .unwrap_or(tracing::Level::INFO);

    let mut fmt_layer = Layer::new()
        .with_span_events(FmtSpan::CLOSE)
        .with_ansi(std::env::var("NO_COLOR").is_err());

    match log_level {
        tracing::Level::DEBUG => fmt_layer = fmt_layer.with_file(true).with_line_number(true),
        tracing::Level::TRACE => {
            fmt_layer = fmt_layer
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_file(true)
                .with_line_number(true)
        }
        _ => {}
    }

    let filter = EnvFilter::new(format!("warn,mermin={log_level}"));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();

    let interfaces_to_test: Vec<String> = if let Some(iface) = interface {
        vec![iface.to_string()]
    } else {
        let all_interfaces: Vec<_> = datalink::interfaces()
            .into_iter()
            .filter(|iface| {
                if iface.is_loopback() {
                    return false;
                }
                if !iface.is_up() {
                    return false;
                }
                true
            })
            .map(|iface| iface.name)
            .collect();

        info!(
            event.name = "diagnose.bpf.interfaces_discovered",
            iface_count = all_interfaces.len(),
            interfaces = ?all_interfaces,
            "discovered interfaces from host namespace"
        );

        let pattern_filtered: Vec<String> = if pattern.is_empty() {
            all_interfaces
        } else {
            all_interfaces
                .into_iter()
                .filter(|iface| IfaceController::matches_pattern(iface, pattern))
                .collect()
        };

        let final_interfaces: Vec<String> = if skip.is_empty() {
            pattern_filtered
        } else {
            pattern_filtered
                .into_iter()
                .filter(|iface| !matches_skip_pattern(iface, skip))
                .collect()
        };

        if final_interfaces.is_empty() {
            return Err(MerminError::internal(
                "no interfaces found matching the criteria",
            ));
        }

        final_interfaces
    };

    info!(
        event.name = "diagnose.bpf.started",
        interface_count = interfaces_to_test.len(),
        interfaces = ?interfaces_to_test,
        "starting BPF filesystem and attach/detach tests"
    );

    capabilities::check_required_capabilities()?;

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!(
            event.name = "diagnose.bpf.rlimit_failed",
            system.rlimit.type = "memlock",
            error.code = ret,
            "failed to remove limit on locked memory"
        );
    }

    let mut ebpf = aya::EbpfLoader::new()
        .set_max_entries("FLOW_STATS_MAP", 1000)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/mermin"
        )))?;

    let kernel_version = KernelVersion::current().unwrap_or(KernelVersion::new(0, 0, 0));
    let use_tcx = kernel_version >= KernelVersion::new(6, 6, 0);
    info!(
        event.name = "diagnose.bpf.kernel_info",
        system.kernel.version = %kernel_version,
        ebpf.attach.method = if use_tcx { "TCX" } else { "netlink" },
        "kernel version determined"
    );

    let bpf_fs_writable = use_tcx && {
        let test_pin_path = "/sys/fs/bpf/mermin_test_map";
        let test_result = ebpf
            .maps()
            .next()
            .and_then(|(_, map)| match map.pin(test_pin_path) {
                Ok(_) => match std::fs::remove_file(test_pin_path) {
                    Ok(_) => Some(()),
                    Err(e) => {
                        warn!(
                            event.name = "diagnose.bpf.bpf_fs_cleanup_failed",
                            error = %e,
                            test_path = %test_pin_path,
                            "failed to cleanup test pin, but /sys/fs/bpf is writable"
                        );
                        Some(())
                    }
                },
                Err(e) => {
                    warn!(
                        event.name = "diagnose.bpf.bpf_fs_pin_failed",
                        error = %e,
                        test_path = %test_pin_path,
                        "failed to pin test map to BPF filesystem"
                    );
                    None
                }
            });
        test_result.is_some()
    };

    let ingress_program: &mut SchedClassifier = ebpf
        .program_mut("mermin_flow_ingress")
        .ok_or_else(|| {
            MerminError::internal("ebpf program 'mermin_flow_ingress' not found in loaded object")
        })?
        .try_into()?;
    ingress_program.load()?;
    info!(
        event.name = "diagnose.bpf.program_loaded",
        "eBPF program loaded successfully"
    );

    let mut results: Vec<InterfaceTestResult> = Vec::new();

    for interface in &interfaces_to_test {
        let result = test_single_interface(interface, ingress_program, bpf_fs_writable, use_tcx)?;
        results.push(result);
    }

    print_test_results(&results, &kernel_version, use_tcx, bpf_fs_writable);

    let passed_count = results.iter().filter(|r| r.overall_status()).count();
    let total_count = results.len();

    if passed_count == 0 {
        return Err(MerminError::internal(format!(
            "all {total_count} interface(s) failed"
        )));
    }

    Ok(())
}

fn test_single_interface(
    interface: &str,
    ingress_program: &mut SchedClassifier,
    bpf_fs_writable: bool,
    use_tcx: bool,
) -> Result<InterfaceTestResult> {
    let mut attach_success = false;
    let mut pin_success: Option<bool> = None;
    let mut link_id: Option<SchedClassifierLinkId> = None;

    if use_tcx {
        let options = TcAttachOptions::TcxOrder(LinkOrder::last());
        match ingress_program.attach_with_options(interface, TcAttachType::Ingress, options) {
            Ok(attached_id) => {
                attach_success = true;
                info!(
                    event.name = "diagnose.bpf.attach_success",
                    network.interface.name = %interface,
                    "✓ successfully attached program to interface"
                );

                if bpf_fs_writable {
                    let pin_path = format!("/sys/fs/bpf/mermin_tcx_{interface}_ingress");
                    match ingress_program.take_link(attached_id) {
                        Ok(link) => {
                            match TryInto::<aya::programs::links::FdLink>::try_into(link) {
                                Ok(fd_link) => {
                                    match fd_link.pin(&pin_path) {
                                        Ok(pinned_fd_link) => {
                                            pin_success = Some(true);
                                            info!(
                                                event.name = "diagnose.bpf.pin_success",
                                                pin_path = %pin_path,
                                                "✓ successfully pinned TCX link"
                                            );
                                            // Drop pinned_fd_link to close the FD, but keep the pin
                                            drop(pinned_fd_link);
                                        }
                                        Err(e) => {
                                            pin_success = Some(false);
                                            error!(
                                                event.name = "diagnose.bpf.pin_failed",
                                                pin_path = %pin_path,
                                                error = %e,
                                                "✗ failed to pin TCX link despite /sys/fs/bpf being writable"
                                            );
                                            // Link was consumed, can't test standard detach
                                        }
                                    }
                                }
                                Err(e) => {
                                    pin_success = Some(false);
                                    warn!(
                                        event.name = "diagnose.bpf.link_conversion_failed",
                                        error = ?e,
                                        "✗ failed to convert link to fd link"
                                    );
                                }
                            }
                        }
                        Err(_e) => {
                            pin_success = Some(false);
                            warn!(
                                event.name = "diagnose.bpf.link_take_failed",
                                "✗ could not take link from program storage"
                            );
                            // Note: attached_id was consumed by take_link attempt, can't use for detach
                        }
                    }
                } else {
                    link_id = Some(attached_id);
                }
            }
            Err(e) => {
                error!(
                    event.name = "diagnose.bpf.attach_failed",
                    network.interface.name = %interface,
                    error = %e,
                    "✗ failed to attach program to interface"
                );
            }
        }
    } else {
        if let Err(e) = aya::programs::tc::qdisc_add_clsact(interface) {
            debug!(
                event.name = "diagnose.bpf.qdisc_add_skipped",
                network.interface.name = %interface,
                error = %e,
                "clsact qdisc add failed (likely already exists)"
            );
        }

        let options = TcAttachOptions::Netlink(NlOptions {
            priority: 50,
            handle: 0,
        });

        match ingress_program.attach_with_options(interface, TcAttachType::Ingress, options) {
            Ok(id) => {
                link_id = Some(id);
                attach_success = true;
                info!(
                    event.name = "diagnose.bpf.attach_success",
                    network.interface.name = %interface,
                    "✓ successfully attached program to interface (netlink mode)"
                );
            }
            Err(e) => {
                error!(
                    event.name = "diagnose.bpf.attach_failed",
                    network.interface.name = %interface,
                    error = %e,
                    "✗ failed to attach program to interface"
                );
            }
        }
    }

    let mut detach_success = false;

    if attach_success {
        if use_tcx {
            let pin_path = format!("/sys/fs/bpf/mermin_tcx_{interface}_ingress");
            match PinnedLink::from_pin(&pin_path) {
                Ok(pinned_link) => match pinned_link.unpin() {
                    Ok(_fd_link) => {
                        detach_success = true;
                        info!(
                            event.name = "diagnose.bpf.detach_success",
                            network.interface.name = %interface,
                            pin_path = %pin_path,
                            "✓ successfully detached program via unpinned link"
                        );
                    }
                    Err(e) => {
                        warn!(
                            event.name = "diagnose.bpf.unpin_failed",
                            pin_path = %pin_path,
                            error = %e,
                            "✗ failed to unpin link, trying standard detach"
                        );
                    }
                },
                Err(_e) => {
                    debug!(
                        event.name = "diagnose.bpf.pin_not_found",
                        pin_path = %pin_path,
                        "pinned link not found, using standard detach"
                    );
                }
            }

            if !detach_success {
                if let Some(id) = link_id {
                    match ingress_program.detach(id) {
                        Ok(_) => {
                            detach_success = true;
                            info!(
                                event.name = "diagnose.bpf.detach_success",
                                network.interface.name = %interface,
                                "✓ successfully detached program (standard detach)"
                            );
                        }
                        Err(e) => {
                            error!(
                                event.name = "diagnose.bpf.detach_failed",
                                network.interface.name = %interface,
                                error = %e,
                                "✗ failed to detach program"
                            );
                        }
                    }
                } else {
                    warn!(
                        event.name = "diagnose.bpf.detach_skipped",
                        network.interface.name = %interface,
                        reason = "no_link_id",
                        "skipping detach test - no link ID available"
                    );
                }
            }
        } else if let Some(id) = link_id {
            match ingress_program.detach(id) {
                Ok(_) => {
                    detach_success = true;
                    info!(
                        event.name = "diagnose.bpf.detach_success",
                        network.interface.name = %interface,
                        "✓ successfully detached program (netlink mode)"
                    );
                }
                Err(e) => {
                    error!(
                        event.name = "diagnose.bpf.detach_failed",
                        network.interface.name = %interface,
                        error = %e,
                        "✗ failed to detach program"
                    );
                }
            }
        } else {
            warn!(
                event.name = "diagnose.bpf.detach_skipped",
                network.interface.name = %interface,
                reason = "no_link_id",
                "skipping detach test - no link ID available"
            );
        }
    } else {
        warn!(
            event.name = "diagnose.bpf.detach_skipped",
            network.interface.name = %interface,
            reason = "attach_failed",
            "skipping detach test - attach operation failed"
        );
    }

    Ok(InterfaceTestResult {
        interface: interface.to_string(),
        bpf_fs_writable,
        attach_success,
        pin_success,
        detach_success,
    })
}

fn print_test_results(
    results: &[InterfaceTestResult],
    kernel_version: &KernelVersion,
    use_tcx: bool,
    bpf_fs_writable: bool,
) {
    let is_multi_interface = results.len() > 1;
    let passed_count = results.iter().filter(|r| r.overall_status()).count();
    let failed_count = results.len() - passed_count;

    if is_multi_interface {
        println!("\n       ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("       BPF Test Results Summary (All Interfaces)");
        println!("       ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("       Total Interfaces Tested: {}", results.len());
        println!("       Passed: {passed_count}  Failed: {failed_count}");
        println!();
        println!("              Interface    BPF FS    Attach    Pin    Detach    Status");
        println!("       ─────────────────────────────────────────────────────────");

        for result in results {
            let bpf_fs_status = if result.bpf_fs_writable {
                "✓ PASS"
            } else {
                "✗ FAIL"
            };
            let attach_status = if result.attach_success {
                "✓ PASS"
            } else {
                "✗ FAIL"
            };
            let pin_status = match result.pin_success {
                Some(true) => "✓ PASS",
                Some(false) => "✗ FAIL",
                None => "N/A",
            };
            let detach_status = if result.detach_success {
                "✓ PASS"
            } else {
                "✗ FAIL"
            };
            let overall_status = if result.overall_status() {
                "✓ PASS"
            } else {
                "✗ FAIL"
            };

            println!(
                "       {:<20} {:<9} {:<8} {:<6} {:<8} {}",
                result.interface,
                bpf_fs_status,
                attach_status,
                pin_status,
                detach_status,
                overall_status
            );
        }

        println!("       ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        if !bpf_fs_writable && use_tcx {
            println!("\n       WARNING: /sys/fs/bpf is not writable!");
            println!("       Mount /sys/fs/bpf as hostPath for orphan cleanup on pod restart.");
        }
    } else {
        let result = &results[0];
        println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("BPF Test Results Summary");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Interface: {}", result.interface);
        println!("Kernel: {kernel_version}");
        println!("Mode: {}", if use_tcx { "TCX" } else { "netlink" });
        println!();
        println!(
            "BPF Filesystem Writeable: {}",
            if result.bpf_fs_writable {
                "✓ PASS"
            } else {
                "✗ FAIL"
            }
        );
        println!(
            "Program Attach:           {}",
            if result.attach_success {
                "✓ PASS"
            } else {
                "✗ FAIL"
            }
        );
        println!(
            "Link Pinning:             {}",
            match result.pin_success {
                Some(true) => "✓ PASS",
                Some(false) => "✗ FAIL",
                None => "N/A (not TCX or BPF FS not writable)",
            }
        );
        println!(
            "Program Detach:           {}",
            if result.detach_success {
                "✓ PASS"
            } else {
                "✗ FAIL"
            }
        );
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        if !result.bpf_fs_writable && use_tcx {
            println!("\n WARNING: /sys/fs/bpf is not writable!");
            println!("   Mount /sys/fs/bpf as hostPath for orphan cleanup on pod restart.");
        }
    }
}
