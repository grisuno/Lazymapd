# root

*Community 0 | 2 files | cohesion 1.00*

## Definition

This community groups 2 file(s) rooted at `lazymapd/src` with dominant language sh (cohesion 1.00). Central symbols: `ScanConfig`, `ScanMode`, `get_protocol_payload`, `get_service_name`, `get_top_ports`, `grab_banner`, `main`, `parse_config`. Core file: `lazymapd/src/main.rs` (17 symbols).

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `install.sh` | sh | utility | 0 | no |
| `lazymapd/src/main.rs` | rs | utility | 17 | no |

## Key Symbols

- `ScanMode` (enum, `lazymapd/src/main.rs:16`) - [derive(Debug, Clone)]
- `ScanConfig` (struct, `lazymapd/src/main.rs:22`) - [derive(Debug, Clone)]
- `main` (function, `lazymapd/src/main.rs:32`)
- `parse_config` (function, `lazymapd/src/main.rs:103`)
- `parse_port_spec` (function, `lazymapd/src/main.rs:172`)
- `get_top_ports` (function, `lazymapd/src/main.rs:197`)
- `print_banner` (function, `lazymapd/src/main.rs:215`)
- `run_fast_scan` (function, `lazymapd/src/main.rs:231`)
- `run_detailed_scan` (function, `lazymapd/src/main.rs:269`)
- `grab_banner` (function, `lazymapd/src/main.rs:310`)
- `get_protocol_payload` (function, `lazymapd/src/main.rs:339`)
- `process_response` (function, `lazymapd/src/main.rs:397`)
- `get_service_name` (function, `lazymapd/src/main.rs:483`)
- `print_fast_results` (function, `lazymapd/src/main.rs:504`)
- `print_detailed_results` (function, `lazymapd/src/main.rs:524`)
- `save_fast_results_to_csv` (function, `lazymapd/src/main.rs:544`)
- `save_detailed_results_to_csv` (function, `lazymapd/src/main.rs:557`)

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 0
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- No cross-community bridges recorded. This community is self-contained.

## Risks

- No scoped security, taint, cycle, or layer risks.

## Open Questions

- Why do 2 file(s) lack file-level docs (e.g. `install.sh`)? What purpose do they serve?
- What would break if the most connected file in root changed?
- Should root be split, given cohesion 1.00?

## Sources

- `install.sh`
- `lazymapd/src/main.rs`
