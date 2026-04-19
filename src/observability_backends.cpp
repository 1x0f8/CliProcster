#include "observability_backends.hpp"

TraceBackendInfo DetectTraceBackends() {
    TraceBackendInfo info;
#ifdef _WIN32
    info.processBackend = "windows-etw-best-effort+polling-fallback";
    info.serviceBackend = "windows-service-polling";
    info.startupBackend = "windows-registry-diff";
    info.driverBackend = "windows-driver-polling";
#else
#ifdef CLIPROCSTER_ENABLE_EBPF
    info.processBackend = "linux-ebpf-stub+/proc-fallback";
    info.ebpfCompiled = true;
#else
    info.processBackend = "linux-proc-polling";
#endif
    info.serviceBackend = "linux-systemd-polling";
    info.startupBackend = "linux-startup-diff";
    info.driverBackend = "linux-proc-modules-polling";
#endif
    return info;
}

