# Aegis Security Gap Analysis: Ingress-Only Visibility

> **SEVERITY**: High (Architectural Limitation)
> **STATUS**: Mitigation Planned (Roadmap: TC Egress Hook)

## 1. The Issue: "Force-Established" State
Aegis currently operates exclusively as an **XDP (eXpress Data Path)** program attached to the **Ingress** hook. This means Aegis sees only *incoming* packets.

### The Blind Spot
When a local process initiates an improved TCP connection (Egress):
1.  **Local -> Remote (SYN)**: Packet leaves the interface. **Aegis does NOT see this.**
2.  **Remote -> Local (SYN-ACK)**: Packet arrives. **Aegis sees this.**

Because Aegis missed step 1, it has no record of a pending connection.

### Current Behavior (The Gap)
To prevent breaking all outgoing network traffic, Aegis employs a "Trust on First Use" (TOFU) policy for SYN-ACK packets:

```rust
// aegis-ebpf/src/main.rs
if syn && ack {
    // We assume this is a response to a valid outgoing SYN
    create_established_state(src, dst, ports);
    return XDP_PASS;
}
```

### The Risk
An attacker who knows or guesses a valid 5-tuple (Source IP, Dest IP, Source Port, Dest Port) can inject a spoofed `SYN-ACK` packet. unique ephemeral ports make this difficult for mass exploitation, but targeted attacks are possible.
Once the spoofed `SYN-ACK` is processed, Aegis creates an **ESTABLISHED** state entry. The attacker can then send data payload packets that match this state, bypassing firewall rules.

## 2. Mitigation Strategy

### Short Term (Current)
- **Randomized Ephemeral Ports**: The kernel's random port selection makes guessing the 5-tuple statistically difficult (1/65535 per attempt).
- **Strict Protocol Validation**: Aegis enforces TCP flag validity (e.g., dropping SYN+FIN, Null scans), reducing the surface for malformed packet injection.

### Long Term (The Fix)
Reference **Roadmap Item A04**: Implement Egress Monitoring.
1.  **Traffic Control (TC) Hook**: Attach a secondary eBPF program to the `TC Egress` hook.
2.  **State Synchronization**:
    - TC Program sees outgoing `SYN`.
    - Updates `CONN_TRACK` map with `CONN_SYN_SENT`.
    - XDP Program (Ingress) only accepts `SYN-ACK` if `CONN_SYN_SENT` exists.

## 3. Conclusion
Users should be aware that strictly speaking, Aegis is currently a **Stateful Ingress Firewall** with **Loose Egress Tracking**. It is highly effective against incoming attacks (Scanning, DoS, Exploits) but treats outgoing traffic initiation as trusted.
