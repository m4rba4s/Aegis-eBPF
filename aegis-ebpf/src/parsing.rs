use aya_ebpf::programs::XdpContext;
use core::mem;

/// Safe packet pointer access with bounds checking.
///
/// IMPORTANT: The eBPF verifier requires seeing the exact pattern:
///   if (ptr + len > data_end) goto error
///
/// The Rust compiler aggressively optimizes comparisons, transforming
/// `ptr + len > end` into `end > ptr` (dropping the +len). This breaks
/// the verifier's bounds tracking.
///
/// We use `core::hint::black_box` to prevent this optimization.
#[inline(always)]
pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    // Compute pointer to start of access
    let ptr = start + offset;

    // Compute end of access region
    // CRITICAL: Use black_box to prevent compiler from optimizing away +len
    let access_end = core::hint::black_box(ptr + len);

    // Bounds check - verifier now sees the correct pattern
    if access_end > end {
        return Err(());
    }

    // Safety: verifier knows [ptr, ptr+len) is within packet
    Ok(ptr as *const T)
}
