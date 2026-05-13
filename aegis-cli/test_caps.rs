use caps::{CapSet, Capability, CapsHashSet};
fn main() {
    let mut keep = CapsHashSet::new();
    keep.insert(Capability::CAP_BPF);
    caps::set(None, CapSet::Effective, &keep).unwrap();
}
