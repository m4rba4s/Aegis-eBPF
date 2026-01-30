use aya_ebpf::programs::TcContext;
use core::mem;

/// Safe pointer access for TC context with bounds checking.
///
/// Uses black_box to prevent compiler from optimizing the bounds check
/// in a way that breaks eBPF verifier pattern matching.
#[inline(always)]
pub fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    let ptr = start + offset;
    let access_end = core::hint::black_box(ptr + len);

    if access_end > end {
        return Err(());
    }

    Ok(ptr as *const T)
}
