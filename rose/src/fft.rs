use rustfft::{num_complex::Complex32, FftPlanner};
use tracing::{info_span, instrument};

#[instrument(skip_all)]
pub fn process(
    host_mem: &mut [Complex32],
    guest_mem: &mut [Complex32],
    scratch: &mut [Complex32],
    planner: &mut FftPlanner<f32>,
) {
    let host_fft_span = info_span!("host fft").entered();
    let fft = planner.plan_fft_forward(host_mem.len());
    fft.process_with_scratch(host_mem, scratch);
    drop(host_fft_span);
    let guest_fft_span = info_span!("guest fft").entered();
    let fft_rev = planner.plan_fft_inverse(guest_mem.len());
    fft.process_with_scratch(guest_mem, scratch);
    drop(guest_fft_span);
    for v in &mut *guest_mem {
        v.im *= -1.0;
    }
    host_mem
        .iter_mut()
        .zip(guest_mem.iter_mut())
        .for_each(|(&mut mut l, &mut r)| l *= r);
    let comb_fft_span = info_span!("combined fft").entered();
    fft_rev.process_with_scratch(host_mem, scratch);
    drop(comb_fft_span);
    println!("done");
    // TODO: Do some thing with this data
}
