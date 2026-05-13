use aya::maps::MapData;
use std::os::unix::io::AsRawFd;
fn check(md: &MapData) -> i32 {
    // try to get fd
    md.fd().as_raw_fd()
}
fn main() {}
