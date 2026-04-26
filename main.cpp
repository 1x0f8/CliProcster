#define NOMINMAX
#include <cstdint>
#include "src/observability_backends.hpp"
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <sddl.h>
#include <winsvc.h>
#include <conio.h>
#else
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

using DWORD = std::uint32_t;
using SIZE_T = std::size_t;
#endif

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <chrono>
#include <cerrno>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Ws2_32.lib")
#endif

namespace {

// The app is still built as one translation unit so the existing internal-linkage
// structure stays intact, but the implementation lives in smaller topical files.
#include "src/core_types.inc"
#include "src/process_collectors.inc"
#include "src/integrations.inc"
#include "src/tui.inc"
#include "src/app.inc"
} // namespace

int main(int argc, char* argv[]) {
    App app;
    return app.run(argc, argv);
}
