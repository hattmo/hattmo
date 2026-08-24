#![feature(maybe_uninit_as_bytes)]
#![feature(core_io_borrowed_buf)]
#![feature(read_buf)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]

//!  Qemu analyzer using ptrace
//!
//!
//!

mod fft;
mod kvm;

use libc::{user_regs_struct, SYS_ioctl, SYS_openat};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::{resource::Resource, trace::SdkTracerProvider};
use rose::{
    GetMapsError, MemoryProcError, RestartCommand, SignalInject, SpawnTracedError, TracedCommand,
    TracedEvent, TracedExitStatus, TracedProcessHandle, WaitEventsError,
};
use rustfft::{num_complex::Complex32, FftPlanner};
use std::{
    cmp::Ordering,
    collections::HashMap,
    env,
    process::Command,
    sync::mpsc::{Receiver, TryRecvError},
    time::Duration,
};
use tracing::{info, info_span, instrument, level_filters::LevelFilter, subscriber};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{layer::SubscriberExt, Registry};

fn build_resource() -> Resource {
    Resource::builder().with_service_name("ROSE").build()
}

#[allow(clippy::missing_panics_doc)]
pub fn main() {
    let span_exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .build()
        .unwrap();

    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(span_exporter)
        .with_resource(build_resource())
        .build();
    let tracer = provider.tracer(env!("CARGO_PKG_NAME"));
    let telemetry = OpenTelemetryLayer::new(tracer);
    let reg = Registry::default().with(telemetry).with(LevelFilter::INFO);
    if subscriber::set_global_default(reg).is_err() {
        eprint!("Could not set the global trace subscriber");
        return;
    };
    if let Err(error) = start_trace() {
        eprintln!("{error:?}");
    };
}

#[allow(unused)]
#[derive(Debug)]
enum JobError {
    WaitEventsError(WaitEventsError),
    SpawTracedError(SpawnTracedError),
    GetMapsError(GetMapsError),
    MemoryProcError(MemoryProcError),
    InvalidArgs,
}

impl From<MemoryProcError> for JobError {
    fn from(value: MemoryProcError) -> Self {
        Self::MemoryProcError(value)
    }
}

impl From<GetMapsError> for JobError {
    fn from(value: GetMapsError) -> Self {
        Self::GetMapsError(value)
    }
}

impl From<WaitEventsError> for JobError {
    fn from(value: WaitEventsError) -> Self {
        Self::WaitEventsError(value)
    }
}

impl From<SpawnTracedError> for JobError {
    fn from(value: SpawnTracedError) -> Self {
        Self::SpawTracedError(value)
    }
}
#[allow(clippy::cast_possible_wrap)]
#[instrument]
fn start_trace() -> Result<(), JobError> {
    info!("starting trace");
    let total_args: Vec<_> = env::args().collect();
    let [_, command, args @ ..] = total_args.as_slice() else {
        return Err(JobError::InvalidArgs);
    }; // Dump first argument

    let mut proc = Command::new(command)
        .args(args)
        .spawn_traced(RestartCommand::Syscall, SignalInject::Suppress)?;
    let proc_hanel = proc.get_handle();
    let (tx, rx) = std::sync::mpsc::channel();
    let fft_job = std::thread::spawn(|| fft_job(rx, proc_hanel));

    let exit = proc.wait_events(|trace_event| {
        if let TracedEvent::Syscall(stop_event, syscall_event) = trace_event {
            let user_regs_struct {
                orig_rax: syscall,
                rsi: arg1,
                ..
            } = stop_event.get_regs()?;
            if syscall == SYS_openat as u64 {
                let path = stop_event.get_string(arg1 as i64)?;
                if path.contains("/dev/kvm") {
                    info!(path, "open kvm");
                    syscall_event.get_return(|return_event| {
                        let user_regs_struct { rax: kvm_fd, .. } = return_event.get_regs()?;
                        info!(kvm_fd);
                        return_event.stop_wait(kvm_fd);
                        Ok(())
                    });
                }
            }
        };
        Ok(())
    })?;
    let TracedExitStatus::Break(kvm_fd) = exit else {
        return Ok(());
    };

    let exit = proc.wait_events(|trace_event| {
        if let TracedEvent::Syscall(stop_event, syscall_event) = trace_event {
            let user_regs_struct {
                orig_rax: syscall,
                rdi: arg0,
                rsi: arg1,
                ..
            } = stop_event.get_regs()?;
            if syscall == SYS_ioctl as u64 && arg0 == kvm_fd && arg1 == kvm::system::KVM_CREATE_VM {
                info!("create vm");
                syscall_event.get_return(|return_event| {
                    let user_regs_struct { rax: vm_fd, .. } = return_event.get_regs()?;
                    info!(vm_fd);
                    return_event.stop_wait(vm_fd);
                    Ok(())
                });
            }
        };
        Ok(())
    })?;

    let TracedExitStatus::Break(vm_fd) = exit else {
        return Ok(());
    };

    proc.wait_events::<(), _>(|trace_event| {
        if let TracedEvent::Syscall(stop_event, _) = trace_event {
            let user_regs_struct {
                orig_rax: syscall,
                rdi: arg0,
                rsi: arg1,
                rdx: arg3,
                ..
            } = stop_event.get_regs()?;
            if syscall == SYS_ioctl as u64 && arg0 == vm_fd {
                if arg1 == kvm::system::KVM_SET_USER_MEMORY_REGION {
                    let mut memory_region_param = [0u8; 32];
                    stop_event.get_memory(arg3 as i64, &mut memory_region_param)?;
                    let guest_phys_addr =
                        u64::from_le_bytes((&memory_region_param[8..16]).try_into().unwrap());
                    let memory_size =
                        u64::from_le_bytes((&memory_region_param[16..24]).try_into().unwrap());
                    let userspace_addr =
                        u64::from_le_bytes((&memory_region_param[24..32]).try_into().unwrap());
                    if tx
                        .send(VirtualMap {
                            guest_addr: guest_phys_addr,
                            host_addr: userspace_addr,
                            size: memory_size,
                        })
                        .is_err()
                    {
                        stop_event.stop_wait(());
                    };
                } else if arg1 == kvm::system::KVM_SET_USER_MEMORY_REGION2 {
                    info!("memory region 2");
                }
            }
        };
        Ok(())
    })?;

    info!("Qemu exited");
    fft_job.join().unwrap()?;
    Ok(())
}

struct VirtualMap {
    guest_addr: u64,
    host_addr: u64,
    size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct MemoryRegion {
    start: u64,
    end: u64,
    size: u64,
}

impl MemoryRegion {
    const fn contains(&self, addr: u64) -> bool {
        addr > self.start && addr < self.end
    }
    const fn from_addrs(start: u64, end: u64) -> Self {
        Self {
            start,
            end,
            size: end - start,
        }
    }
    const fn from_size(start: u64, size: u64) -> Self {
        Self {
            start,
            end: start + size,
            size,
        }
    }
}

#[allow(clippy::needless_pass_by_value)]
fn fft_job(
    guest_changes_channel: Receiver<VirtualMap>,
    proc_handle: TracedProcessHandle,
) -> Result<(), JobError> {
    let _fft_span = info_span!("fft job").entered();
    let mut guest_maps_cache: HashMap<u64, MemoryRegion> = HashMap::new();
    let mut guest_maps: Vec<MemoryRegion> = Vec::new();
    let mut host_maps_cache: Vec<MemoryRegion> = Vec::new();
    let mut host_maps: Vec<MemoryRegion> = Vec::new();
    let mut guest_mem: Vec<u8> = Vec::new();
    let mut host_mem: Vec<u8> = Vec::new();
    let mut scratch: Vec<u8> = Vec::new();
    let mut planner = FftPlanner::new();
    'outer: loop {
        let _span = info_span!("processing memory").entered();
        let mut guest_updates = false;
        let check_guest_span = info_span!("check guest").entered();
        loop {
            match guest_changes_channel.try_recv() {
                Ok(VirtualMap {
                    guest_addr,
                    host_addr,
                    size,
                }) => {
                    if size == 0 {
                        guest_maps_cache.remove(&guest_addr);
                    } else {
                        guest_maps_cache
                            .insert(guest_addr, MemoryRegion::from_size(host_addr, size));
                    }
                    guest_updates = true;
                }
                Err(TryRecvError::Empty) => {
                    break;
                }
                Err(TryRecvError::Disconnected) => {
                    break 'outer;
                }
            }
        }
        if guest_updates {
            guest_maps = guest_maps_cache.values().copied().collect();
            guest_maps.sort();
        }
        drop(check_guest_span);
        let check_host_span = info_span!("check host").entered();
        let new_host_maps = proc_handle
            .get_maps()?
            .into_iter()
            .filter(|map| {
                map.write
                    && map
                        .path
                        .as_ref()
                        .is_some_and(|path| (path == "[heap]") || (path == "[stack]"))
            })
            .map(|map| MemoryRegion::from_addrs(map.start_addr, map.end_addr))
            .collect();
        if new_host_maps != host_maps_cache || guest_updates {
            host_maps_cache = new_host_maps;

            host_maps = host_maps_cache
                .iter()
                .copied()
                .map(|host| vec![host])
                .flat_map(|mut host| {
                    for guest in &guest_maps {
                        host = intersections(guest, host);
                    }
                    host.into_iter()
                })
                .collect();
        }
        drop(check_host_span);
        if let Some((host, guest, scratch)) = read_memory(
            &guest_maps,
            &host_maps,
            &mut host_mem,
            &mut guest_mem,
            &mut scratch,
            &proc_handle,
        )? {
            fft::process(host, guest, scratch, &mut planner);
        };
        // process FFT
    }
    Ok(())
}
#[allow(clippy::cast_possible_truncation)]
#[instrument(skip_all)]
fn read_memory<'host, 'guest, 'scratch>(
    guest_maps: &[MemoryRegion],
    host_maps: &[MemoryRegion],
    host_mem: &'host mut Vec<u8>,
    guest_mem: &'guest mut Vec<u8>,
    scratch: &'scratch mut Vec<u8>,
    handle: &TracedProcessHandle,
) -> Result<
    Option<(
        &'host mut [Complex32],
        &'guest mut [Complex32],
        &'scratch mut [Complex32],
    )>,
    MemoryProcError,
> {
    let read_host_span = info_span!("read host mem").entered();
    let mut start_offset = 0usize;
    let mut end_offset = 0usize;
    for host in host_maps {
        end_offset = host.size as usize + start_offset;
        if host_mem.len() < end_offset {
            host_mem.resize(end_offset, 0);
        }
        let new_mem = &mut host_mem[start_offset..end_offset];

        handle.get_memory_proc(host.start, new_mem)?;
        start_offset += host.size as usize;
    }
    let new_host_size = end_offset;
    drop(read_host_span);
    let read_guest_span = info_span!("read guest mem").entered();

    let mut start_offset = 0usize;
    let mut end_offset = 0usize;
    for guest in guest_maps {
        end_offset = guest.size as usize + start_offset;
        if guest_mem.len() < end_offset {
            guest_mem.resize(end_offset, 0);
        }
        let new_mem = &mut guest_mem[start_offset..end_offset];

        handle.get_memory_proc(guest.start, new_mem)?;
        start_offset += guest.size as usize;
    }
    let new_guest_size = end_offset;
    drop(read_guest_span);

    let fixing_buffers_span = info_span!("fixing buffers").entered();
    if new_host_size == 0 || new_guest_size == 0 {
        return Ok(None);
    }
    let best_size = match new_host_size.cmp(&new_guest_size) {
        Ordering::Less | Ordering::Equal => nearest_pow2(new_guest_size),
        Ordering::Greater => nearest_pow2(new_host_size),
    };
    if host_mem.len() < best_size {
        host_mem.resize(best_size, 0);
    }
    if guest_mem.len() < best_size {
        guest_mem.resize(best_size, 0);
    }
    if scratch.len() < best_size {
        scratch.resize(best_size, 0);
    }

    drop(fixing_buffers_span);
    unsafe {
        let (_, host_out, _) = host_mem[..best_size].align_to_mut::<Complex32>();
        let (_, guest_out, _) = guest_mem[..best_size].align_to_mut::<Complex32>();
        let (_, scratch_out, _) = scratch[..best_size].align_to_mut::<Complex32>();
        Ok(Some((host_out, guest_out, scratch_out)))
    }
}

fn intersections(guest: &MemoryRegion, host: Vec<MemoryRegion>) -> Vec<MemoryRegion> {
    let mut out = Vec::new();
    for host in host {
        if guest.end < host.start || guest.start > host.end {
            out.push(host);
        } else {
            if host.contains(guest.start) {
                out.push(MemoryRegion::from_addrs(host.start, guest.start));
            }
            if host.contains(guest.end) {
                out.push(MemoryRegion::from_addrs(guest.end, host.end));
            }
        }
    }
    out
}

fn nearest_pow2(mut test: usize) -> usize {
    if test.count_ones() == 1 {
        return test;
    }
    for i in 0..usize::BITS {
        if test == 0 {
            return 1 << i;
        }
        test >>= 1;
    }
    unreachable!("Should end always");
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    pub fn intersections_test() {
        let res = intersections(
            &MemoryRegion::from_addrs(7, 9),
            vec![MemoryRegion::from_addrs(6, 11)],
        );
        let expected = vec![
            MemoryRegion::from_addrs(6, 7),
            MemoryRegion::from_addrs(9, 11),
        ];
        assert!(res == expected);
    }

    #[test]
    fn nearest_pow2_test() {
        let actual = nearest_pow2(100);
        let expected = 128;
        assert!(actual == expected);

        let actual = nearest_pow2(2);
        let expected = 2;
        assert!(actual == expected);
    }
}
