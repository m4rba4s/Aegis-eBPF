import re
import sys

with open('aegis-cli/src/main.rs', 'r') as f:
    content = f.read()

# We need to extract the events loop logic.
# Starts around `let events_map = bpf.take_map("EVENTS")`
# Ends at `let geo_db = geo::GeoLookup::open().map(Arc::new);`

start_idx = content.find('            // Take ownership of EVENTS (IPv4)')
end_idx = content.find('            // Initialize GeoIP database')

if start_idx == -1 or end_idx == -1:
    print("Could not find bounds")
    sys.exit(1)

loop_code = content[start_idx:end_idx]

# Remove indentation
lines = loop_code.split('\n')
clean_lines = []
for line in lines:
    if line.startswith('            '):
        clean_lines.append(line[12:])
    elif line == '':
        clean_lines.append(line)
    else:
        clean_lines.append(line)
loop_code_clean = '\n'.join(clean_lines)

# Generate event_loop.rs
event_loop_code = f"""use std::sync::{{Arc, Mutex}};
use std::collections::VecDeque;
use std::net::{{Ipv4Addr, Ipv6Addr}};
use aya::maps::perf::AsyncPerfEventArray;
use aya::maps::MapData;
use aya::util::online_cpus;
use bytes::BytesMut;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use aegis_common::{{
    PacketLog, PacketLogIpv6, FlowKey, 
    THREAT_SCAN_XMAS, THREAT_SCAN_NULL, THREAT_SCAN_SYNFIN, THREAT_SCAN_PORT,
    THREAT_FLOOD_SYN, THREAT_BLOCKLIST, THREAT_INCOMING_SYN, THREAT_EGRESS_BLOCKED, THREAT_NONE,
    THREAT_IPV6_EXT_CHAIN, THREAT_IPV6_ROUTING_TYPE0, THREAT_IPV6_FRAGMENT, THREAT_IPV6_HOP_BY_HOP,
    REASON_DEFAULT, REASON_WHITELIST, REASON_CONNTRACK, REASON_MANUAL_BLOCK,
    REASON_CIDR_FEED, REASON_PORTSCAN, REASON_TCP_ANOMALY, REASON_RATELIMIT,
    REASON_IPV6_POLICY, REASON_MALFORMED, REASON_EGRESS_BLOCK
}};
use crate::format;
use crate::cef_export;
use crate::pcap;
use crate::alerts;
use crate::config::{{LoggingConfig, WebhooksConfig}};

pub struct EventLoopContext {{
    pub logs_arc: Arc<Mutex<VecDeque<String>>>,
    pub blocklist_arc: Arc<Mutex<aya::maps::HashMap<MapData, FlowKey, u32>>>,
    pub remote_log_base: Option<String>,
    pub logging_cfg: LoggingConfig,
    pub webhooks_cfg: WebhooksConfig,
    pub pcap_on: bool,
}}

pub fn spawn_event_loops(
    bpf: &mut aya::Ebpf,
    ctx: EventLoopContext,
) -> Result<(), anyhow::Error> {{
    let logs_arc = ctx.logs_arc;
    let blocklist_arc = ctx.blocklist_arc;
    let remote_log_base = ctx.remote_log_base;
    let logging_cfg = ctx.logging_cfg;
    let webhooks_cfg = ctx.webhooks_cfg;
    let pcap_on = ctx.pcap_on;

{loop_code_clean}
    // Spawn event poller globally
    tokio::spawn(async move {{
        loop {{
            event_futures.next().await;
        }}
    }});

    Ok(())
}}
"""

with open('aegis-cli/src/event_loop.rs', 'w') as f:
    f.write(event_loop_code)

# Replace the loop code and the tokio::spawn instances in main.rs
new_content = content[:start_idx] + """
            // --- SPAWN EVENT LOOPS ---
            let ctx = event_loop::EventLoopContext {
                logs_arc: logs_arc.clone(),
                blocklist_arc: blocklist_arc.clone(),
                remote_log_base: cfg.remote_log.clone(),
                logging_cfg: sys_cfg.logging.clone(),
                webhooks_cfg: sys_cfg.webhooks.clone(),
                pcap_on: sys_cfg.pcap.enabled,
            };
            event_loop::spawn_event_loops(&mut bpf, ctx)?;
            
""" + content[end_idx:]

# Remove the two `tokio::spawn` loops for `event_futures`
new_content = re.sub(
    r'\s*tokio::spawn\(async move \{\s*loop \{\s*event_futures\.next\(\)\.await;\s*\}\s*\}\);', 
    '', 
    new_content
)

new_content = new_content.replace('mod map_manager;', 'mod map_manager;\nmod event_loop;')

# Remove unused imports in main.rs if they were exclusively for event loop
# Actually let's let cargo fix handle imports, or just leave them.

with open('aegis-cli/src/main.rs', 'w') as f:
    f.write(new_content)

print("Extraction complete")
