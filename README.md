# CliProcster

CliProcster is a cross-platform console/TUI process monitor. It uses WinAPI on Windows and `/proc` on Linux, with keyboard navigation, process grouping, tree/subtree views, hunt alerts, rules, SIEM event export, and Prometheus textfile metrics.

## Build

### Windows

Open a Developer PowerShell for Visual Studio, then run:

```powershell
MSBuild CliProcster.sln /p:Configuration=Debug /p:Platform=x64
```

The binary is written to:

```text
x64\Debug\CliProcster.exe
```

### Linux

Install a C++17 compiler and CMake, then run:

```bash
cmake -S . -B build
cmake --build build
```

The binary is written to:

```text
build/CliProcster
```

## Run

Windows:

```powershell
x64\Debug\CliProcster.exe
```

Linux:

```bash
./build/CliProcster
```

Useful options:

```powershell
x64\Debug\CliProcster.exe --filter powershell
x64\Debug\CliProcster.exe --view tree --pid 1234
x64\Debug\CliProcster.exe --sort cpu
x64\Debug\CliProcster.exe --rules alert_rules.example.txt
x64\Debug\CliProcster.exe --siem-events cliprocster_events.ndjson
x64\Debug\CliProcster.exe --prometheus-file cliprocster.prom
x64\Debug\CliProcster.exe --export-json cliprocster_snapshot.json
```

Linux uses the same flags:

```bash
./build/CliProcster --filter ssh
./build/CliProcster --sort cpu
./build/CliProcster --rules alert_rules.example.txt
./build/CliProcster --siem-events cliprocster_events.ndjson
./build/CliProcster --prometheus-file cliprocster.prom
```

## Tabs

Use the numeric tab keys:

```text
1  Processes
2  Registry Run keys
3  Kernel drivers
```

The process tab is the main monitor. Registry and driver tabs are read-only trace views. On Linux, the registry tab explains that the Windows registry is not available, and the driver tab reads loaded modules from `/proc/modules`.

## Navigation

```text
Up/Down       move cursor
PgUp/PgDn     page
Home/End      jump
Enter         select focused process
Esc           back/cancel/deselect
Tab           focus right pane when visible
[ / ]         cycle right pane mode
/             filter
s             cycle sort
v             cycle view
d             deselect
q             quit
F1 or ?       help
```

## Stable CPU/Memory Browsing

CPU and memory sorting are volatile because the ranking can change every refresh. CliProcster pins the visible order while browsing those sorts so the row under your cursor does not jump around.

The order remains pinned while you browse and filter. It is reset when you change sort, change view, switch away from the process tab, or deselect.

## Hunt Mode

Hunt mode watches one process for abnormal behavior.

```text
x  hunt focused process or right-pane member
h  toggle hunt on selected process
```

Current hunt signals:

```text
CPU spike:       CPU >= 18%
Memory jump:     working set increases by >= 80 MB
Missing target:  watched PID disappears
Reacquire:       PID disappears but a process with the same name appears
```

Hunt alerts are shown in the TUI, stored in the internal event hub, and exported through the SIEM/Prometheus integrations when enabled.

## Alert Rules

Rules are loaded with:

```powershell
x64\Debug\CliProcster.exe --rules alert_rules.example.txt
```

Rule format:

```text
Name field op value
```

Supported fields:

```text
cpu, mem_mb, threads, pid, ppid, name, path, service, sid
```

Supported operators:

```text
gt, gte, lt, lte, eq, contains
```

Example:

```text
HighCPU cpu gte 50
LargeMemory mem_mb gt 1024
PowerShellSeen name contains powershell
ManyThreads threads gt 200
```

## SIEM Export

Append durable JSON-line events:

```powershell
x64\Debug\CliProcster.exe --rules alert_rules.example.txt --siem-events cliprocster_events.ndjson
```

Each line is an event:

```json
{"ts":1776590597086,"seq":7,"type":"RuleAlertTriggered","pid":65300,"message":"PowerShellSeen matched powershell.exe"}
```

This is suitable for filebeat, fluent-bit, Splunk forwarders, Elastic, Sentinel ingestion agents, or custom collectors.

## Prometheus

Write Prometheus textfile metrics:

```powershell
x64\Debug\CliProcster.exe --prometheus-file cliprocster.prom
```

Metrics include:

```text
cliprocster_processes
cliprocster_kernel_processes
cliprocster_process_cpu_percent_sum
cliprocster_process_working_set_bytes_sum
cliprocster_services
cliprocster_kernel_drivers
cliprocster_registry_run_entries
cliprocster_hunt_active
cliprocster_hunt_alert
cliprocster_rules_loaded
cliprocster_rule_alerts_buffered_total
cliprocster_hunt_alerts_buffered_total
```

For a normal Prometheus scrape, use the textfile collector pattern or have a small local exporter serve this file.

## Architecture

Main pieces in `main.cpp`:

```text
ProcessCollector      WinAPI collection on Windows, /proc collection on Linux
ProcessRepository     Snapshot cache and pause/live behavior
UiState               Cursor, selection, tabs, panes, hunt state
Renderer              Deterministic ANSI TUI rendering
InputController       Key-to-command mapping
CommandDispatcher     State transitions and side effects
HuntService           Focused process anomaly watcher
AlertRuleService      Rule loading/evaluation
IntegrationHub        Internal event buffer
IntegrationExporter   SIEM NDJSON and Prometheus textfile output
SnapshotExporter      JSON snapshot export
```

## Next Good Steps

Planned natural extensions:

```text
Local HTTP API: /snapshot, /events, /metrics
More rule fields: child count, signer, hash, command line
Rule config format: TOML/JSON/YAML
ETW-backed process start/stop tracing
Linux proc connector/eBPF process start/stop tracing
Driver signing metadata
Registry diff history
Service start/stop history
```
