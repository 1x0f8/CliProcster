#pragma once

#include <string>

struct TraceBackendInfo {
    std::string processBackend;
    std::string serviceBackend;
    std::string startupBackend;
    std::string driverBackend;
    bool ebpfCompiled = false;
};

TraceBackendInfo DetectTraceBackends();

