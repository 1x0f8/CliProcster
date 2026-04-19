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

constexpr const char* AppName = "CliProcster";

namespace Ansi {
constexpr const char* Reset = "\x1b[0m";
constexpr const char* Dim = "\x1b[38;5;245m";
constexpr const char* Grey = "\x1b[38;5;240m";
constexpr const char* Green = "\x1b[38;5;120m";
constexpr const char* LightGreenBg = "\x1b[48;5;22m\x1b[38;5;156m";
constexpr const char* Orange = "\x1b[38;5;214m";
constexpr const char* OrangeBg = "\x1b[48;5;94m\x1b[38;5;230m";
constexpr const char* FocusBg = "\x1b[48;5;24m\x1b[38;5;231m";
constexpr const char* Red = "\x1b[38;5;203m";
constexpr const char* RedBg = "\x1b[48;5;52m\x1b[38;5;224m";
constexpr const char* Cyan = "\x1b[38;5;117m";
constexpr const char* White = "\x1b[38;5;255m";
} // namespace Ansi

enum class SortMode { Cpu, Memory, Pid, Name };
enum class ViewMode { Table, Tree, Kernel };
enum class AppTab { Processes, Registry, Drivers };
enum class RightPaneMode { Members, Details, Children, Services, Drivers, Registry };
enum class FocusPane { ProcessList, GroupMembers };
enum class NotificationKind { Info, Success, Warning, Error };
enum class Command {
    None,
    Quit,
    MoveUp,
    MoveDown,
    PageUp,
    PageDown,
    JumpTop,
    JumpBottom,
    ScrollPathLeft,
    ScrollPathRight,
    FocusNextPane,
    ActivateSelection,
    Deselect,
    Back,
    NextRightPaneMode,
    PrevRightPaneMode,
    HuntFocused,
    SubtreeFocused,
    ToggleHelp,
    CycleView,
    CycleSort,
    PromptFilter,
    ClearContext,
    PromptSubtree,
    RequestKill,
    ConfirmYes,
    ConfirmNo,
    ToggleHunt,
    ShowProcessTab,
    ShowRegistryTab,
    ShowDriversTab,
    FasterRefresh,
    SlowerRefresh,
    TogglePause,
    ExportSnapshot
};
enum class EventType { ProcessKilled, HuntAlertTriggered, RuleAlertTriggered, FilterChanged, ViewChanged, SnapshotExported, KillFailed };

struct CommandMetadata {
    Command command = Command::None;
    const char* keys = "";
    const char* description = "";
    const char* category = "";
};

struct ProcessTimes {
    unsigned long long processTicks = 0;
    unsigned long long systemTicks = 0;
};

struct AccessField {
    std::string value;
    std::string status;

    bool ok() const {
        return !value.empty();
    }

    std::string display(const std::string& fallback = "<denied>") const {
        return ok() ? value : fallback;
    }
};

struct ProcessInfo {
    DWORD pid = 0;
    DWORD parentPid = 0;
    DWORD threads = 0;
    double cpu = 0.0;
    SIZE_T workingSet = 0;
    std::string name;
    AccessField path;
    AccessField sid;
    std::string service;
    std::string commandLine;
    std::string signer = "unknown";
    std::string hash = "unknown";
};

struct ProcessGroup {
    std::string name;
    int count = 0;
    double cpu = 0.0;
    SIZE_T workingSet = 0;
    DWORD threads = 0;
    std::vector<DWORD> pids;
};

struct SystemEntry {
    std::string type;
    std::string name;
    std::string detail;
    DWORD pid = 0;
    std::string signer = "unknown";
    std::string hash = "unknown";
};

struct ProcessSnapshot {
    std::vector<ProcessInfo> processes;
    std::vector<SystemEntry> services;
    std::vector<SystemEntry> drivers;
    std::vector<SystemEntry> registryKeys;
    std::chrono::system_clock::time_point capturedAt = std::chrono::system_clock::now();
};

struct ProcessDto {
    DWORD pid = 0;
    DWORD parentPid = 0;
    std::string name;
    std::string path;
    std::string sid;
    std::string service;
    std::string commandLine;
    std::string signer;
    std::string hash;
    int childCount = 0;
    double cpu = 0.0;
    SIZE_T workingSet = 0;
    DWORD threads = 0;
};

struct SnapshotDto {
    std::vector<ProcessDto> processes;
    DWORD selectedPid = 0;
    std::string view;
    std::string filter;
    bool huntActive = false;
    DWORD huntPid = 0;
    std::string huntAlert;
    int recentProcessEvents = 0;
    int recentServiceEvents = 0;
    int recentStartupEvents = 0;
    int recentDriverEvents = 0;
};

struct AppOptions {
    SortMode sortMode = SortMode::Cpu;
    ViewMode viewMode = ViewMode::Table;
    std::string filter;
    DWORD subtreePid = 0;
    int refreshMs = 200;
    int rowLimit = 0;
    bool includeKernel = true;
    bool once = false;
    std::string exportPath;
    std::string rulesPath;
    std::string siemEventsPath;
    std::string prometheusPath;
    bool httpApi = false;
    std::string httpBind = "127.0.0.1";
    int httpPort = 8765;
};

struct HuntState {
    bool active = false;
    DWORD pid = 0;
    std::string name;
    SIZE_T lastWorkingSet = 0;
    SIZE_T peakWorkingSet = 0;
    double lastCpu = 0.0;
    double peakCpu = 0.0;
    double cpuAlert = 18.0;
    SIZE_T memoryJumpAlert = 80ull * 1024ull * 1024ull;
    std::string alert;
    std::string status;
    int missingFrames = 0;
};

struct Notification {
    NotificationKind kind = NotificationKind::Info;
    std::string text;
    int ttlFrames = 0;
};

struct ActionEvent {
    std::size_t sequence = 0;
    EventType type = EventType::FilterChanged;
    DWORD pid = 0;
    std::string text;
    long long timestampMs = 0;
};

enum class HistoryKind { Process, Service, Startup, Driver };

struct HistoryEvent {
    std::size_t sequence = 0;
    HistoryKind kind = HistoryKind::Process;
    std::string action;
    std::string key;
    std::string name;
    std::string detail;
    DWORD pid = 0;
    long long timestampMs = 0;
};

struct ConsoleSize {
    int width = 120;
    int height = 35;

    bool operator==(const ConsoleSize& other) const {
        return width == other.width && height == other.height;
    }

    bool operator!=(const ConsoleSize& other) const {
        return !(*this == other);
    }
};

struct DisplayRow {
    DWORD pid = 0;
    std::string label;
    bool gone = false;
    int goneAge = 0;
};

struct UiState {
    int selectedIndex = 0;
    DWORD selectedPid = 0;
    bool selectionActive = true;
    int processSelectedIndex = 0;
    int processScroll = 0;
    int startupSelectedIndex = 0;
    int startupScroll = 0;
    int driverSelectedIndex = 0;
    int driverScroll = 0;
    AppTab selectedSystemTab = AppTab::Registry;
    std::string selectedSystemKey;
    bool systemSelectionActive = false;
    bool sortOrderPinned = false;
    std::vector<DWORD> heldRowOrder;
    AppTab activeTab = AppTab::Processes;
    FocusPane focusPane = FocusPane::ProcessList;
    RightPaneMode rightPaneMode = RightPaneMode::Members;
    int rightSelectedIndex = 0;
    int rightScroll = 0;
    int scroll = 0;
    int pathScroll = 0;
    bool paused = false;
    bool showHelp = false;
    bool confirmKill = false;
    DWORD pendingKillPid = 0;
    std::set<DWORD> killRequested;
    std::unordered_map<DWORD, ProcessInfo> fadingGone;
    std::unordered_map<DWORD, int> fadingAge;
    HuntState hunt;
    Notification message;

    void notify(NotificationKind kind, const std::string& text, int ttl = 18) {
        message = { kind, text, ttl };
    }
};

std::string ToLower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text;
}

bool ContainsText(const std::string& haystack, const std::string& needle) {
    return ToLower(haystack).find(ToLower(needle)) != std::string::npos;
}

bool MatchesQuery(const std::string& haystack, const std::string& query) {
    std::istringstream terms(query);
    for (std::string term; terms >> term;) {
        if (!ContainsText(haystack, term)) {
            return false;
        }
    }
    return true;
}

std::string StartupAreaName() {
#ifdef _WIN32
    return "registry";
#else
    return "startup";
#endif
}

std::string StartupAreaTitle() {
#ifdef _WIN32
    return "REGISTRY RUN KEYS";
#else
    return "STARTUP ENTRIES";
#endif
}

std::string StartupAreaColumnTitle() {
#ifdef _WIN32
    return "KEY / VALUE";
#else
    return "ENTRY / TARGET";
#endif
}

#ifdef _WIN32
std::string WideToUtf8(const wchar_t* text) {
    if (!text || text[0] == L'\0') {
        return {};
    }

    const int size = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 1) {
        return {};
    }

    std::string converted(static_cast<std::size_t>(size - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, -1, &converted[0], size, nullptr, nullptr);
    return converted;
}

std::string WideToUtf8(const char* text) {
    return text ? std::string(text) : std::string();
}
#endif

std::string TrimTo(std::string text, std::size_t width) {
    if (text.size() <= width) {
        return text + std::string(width - text.size(), ' ');
    }
    if (width <= 3) {
        return text.substr(0, width);
    }
    return text.substr(0, width - 3) + "...";
}

std::string SliceTo(const std::string& text, std::size_t offset, std::size_t width) {
    if (offset >= text.size()) {
        return std::string(width, ' ');
    }
    return TrimTo(text.substr(offset), width);
}

std::string MemoryMb(SIZE_T bytes) {
    std::ostringstream out;
    out << std::fixed << std::setprecision(1) << (static_cast<double>(bytes) / (1024.0 * 1024.0));
    return out.str();
}

std::string SortName(SortMode mode) {
    switch (mode) {
    case SortMode::Cpu: return "CPU";
    case SortMode::Memory: return "Memory";
    case SortMode::Pid: return "PID";
    case SortMode::Name: return "Name";
    }
    return "CPU";
}

std::string ViewName(ViewMode mode) {
    switch (mode) {
    case ViewMode::Table: return "table";
    case ViewMode::Tree: return "tree";
    case ViewMode::Kernel: return "kernel";
    }
    return "table";
}

std::string TabName(AppTab tab) {
    switch (tab) {
    case AppTab::Processes: return "processes";
    case AppTab::Registry: return StartupAreaName();
    case AppTab::Drivers: return "drivers";
    }
    return "processes";
}

std::string RightPaneModeName(RightPaneMode mode) {
    switch (mode) {
    case RightPaneMode::Members: return "members";
    case RightPaneMode::Details: return "details";
    case RightPaneMode::Children: return "children";
    case RightPaneMode::Services: return "services";
    case RightPaneMode::Drivers: return "drivers";
    case RightPaneMode::Registry: return StartupAreaName();
    }
    return "members";
}

const std::vector<CommandMetadata>& CommandRegistry() {
    static const std::vector<CommandMetadata> commands{
        { Command::ToggleHelp, "? / F1", "show or hide help", "general" },
        { Command::Back, "Esc", "back, cancel, leave right pane, or deselect", "general" },
        { Command::Quit, "q", "quit", "general" },
        { Command::MoveUp, "Up/Down", "move focused cursor", "navigation" },
        { Command::PageUp, "PgUp/PgDn", "page focused pane", "navigation" },
        { Command::PageUp, "Tab+Up/Down", "page focused pane", "navigation" },
        { Command::JumpTop, "Home/End", "jump to top or bottom", "navigation" },
        { Command::FocusNextPane, "Tab", "switch process list and right pane", "navigation" },
        { Command::ActivateSelection, "Enter", "select focused item", "selection" },
        { Command::Deselect, "d", "deselect current process", "selection" },
        { Command::NextRightPaneMode, "] / [", "switch right pane mode", "right pane" },
        { Command::HuntFocused, "x", "hunt focused process/member for CPU/memory/missing alerts", "actions" },
        { Command::ToggleHunt, "h", "toggle hunt on selected process", "actions" },
        { Command::ShowProcessTab, "1", "show process table tab", "tabs" },
        { Command::ShowRegistryTab, "2", "show startup/registry tab", "tabs" },
        { Command::ShowDriversTab, "3", "show kernel driver tab", "tabs" },
        { Command::SubtreeFocused, "g", "set focused process/member as subtree root", "actions" },
        { Command::RequestKill, "k", "confirm kill selected process", "actions" },
        { Command::PromptFilter, "/", "set filter", "views" },
        { Command::CycleSort, "s", "cycle sort", "views" },
        { Command::CycleView, "v", "cycle table/tree/kernel", "views" },
        { Command::ClearContext, "c", "clear filter/subtree/path offset", "views" },
        { Command::ExportSnapshot, "e", "export JSON snapshot", "integration" },
        { Command::TogglePause, "Space", "pause or resume refresh", "runtime" },
        { Command::FasterRefresh, "+ / -", "change refresh interval", "runtime" }
    };
    return commands;
}

#ifdef _WIN32
std::string FormatLastError(DWORD error = GetLastError()) {
    if (error == 0) {
        return "no error detail";
    }

    LPSTR buffer = nullptr;
    const DWORD size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPSTR>(&buffer),
        0,
        nullptr
    );

    std::string text = size != 0 && buffer ? buffer : "unknown Windows error";
    if (buffer) {
        LocalFree(buffer);
    }

    while (!text.empty() && (text.back() == '\r' || text.back() == '\n' || text.back() == ' ')) {
        text.pop_back();
    }
    return text;
}
#else
std::string FormatLastError(int error = errno) {
    return std::strerror(error);
}
#endif

#ifdef _WIN32
unsigned long long FileTimeToTicks(const FILETIME& value) {
    ULARGE_INTEGER converted{};
    converted.LowPart = value.dwLowDateTime;
    converted.HighPart = value.dwHighDateTime;
    return converted.QuadPart;
}
#endif

bool IsKernelProcess(const ProcessInfo& process) {
    const std::string name = ToLower(process.name);
    return process.pid == 0 ||
           process.pid == 4 ||
           process.parentPid == 4 ||
           name == "system" ||
           name == "idle" ||
           name == "system idle process" ||
           name == "registry";
}

bool ComesBefore(const ProcessInfo& left, const ProcessInfo& right, SortMode sortMode) {
    switch (sortMode) {
    case SortMode::Cpu:
        return left.cpu == right.cpu ? left.pid < right.pid : left.cpu > right.cpu;
    case SortMode::Memory:
        return left.workingSet == right.workingSet ? left.pid < right.pid : left.workingSet > right.workingSet;
    case SortMode::Pid:
        return left.pid < right.pid;
    case SortMode::Name:
        return ToLower(left.name) == ToLower(right.name) ? left.pid < right.pid : ToLower(left.name) < ToLower(right.name);
    }
    return left.pid < right.pid;
}

long long UnixTimeMs() {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
}

std::string EventTypeName(EventType type) {
    switch (type) {
    case EventType::ProcessKilled: return "ProcessKilled";
    case EventType::HuntAlertTriggered: return "HuntAlertTriggered";
    case EventType::RuleAlertTriggered: return "RuleAlertTriggered";
    case EventType::FilterChanged: return "FilterChanged";
    case EventType::ViewChanged: return "ViewChanged";
    case EventType::SnapshotExported: return "SnapshotExported";
    case EventType::KillFailed: return "KillFailed";
    }
    return "Unknown";
}

std::string JsonEscape(const std::string& value) {
    std::ostringstream escaped;
    for (unsigned char c : value) {
        switch (c) {
        case '\\': escaped << "\\\\"; break;
        case '"': escaped << "\\\""; break;
        case '\n': escaped << "\\n"; break;
        case '\r': escaped << "\\r"; break;
        case '\t': escaped << "\\t"; break;
        default:
            if (c < 0x20) {
                escaped << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
            } else {
                escaped << static_cast<char>(c);
            }
            break;
        }
    }
    return escaped.str();
}

bool MatchesFilter(const ProcessInfo& process, const AppOptions& options) {
    if (!options.includeKernel && IsKernelProcess(process)) {
        return false;
    }
    if (options.viewMode == ViewMode::Kernel && !IsKernelProcess(process)) {
        return false;
    }
    if (options.filter.empty()) {
        return true;
    }

    const std::string haystack = process.name + " " + process.commandLine + " " + process.path.value + " " + process.sid.value + " " +
        process.service + " " + std::to_string(process.pid);
    return MatchesQuery(haystack, options.filter);
}

bool MatchesFilter(const SystemEntry& entry, const AppOptions& options) {
    if (options.filter.empty()) {
        return true;
    }
    return MatchesQuery(entry.type + " " + entry.name + " " + entry.detail + " " + std::to_string(entry.pid), options.filter);
}

std::vector<SystemEntry> FilterSystemEntries(const std::vector<SystemEntry>& entries, const AppOptions& options) {
    std::vector<SystemEntry> filtered;
    for (const auto& entry : entries) {
        if (MatchesFilter(entry, options)) {
            filtered.push_back(entry);
        }
    }
    return filtered;
}

std::string TrimCopy(const std::string& value) {
    const auto first = std::find_if_not(value.begin(), value.end(), [](unsigned char c) {
        return std::isspace(c) != 0;
    });
    const auto last = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char c) {
        return std::isspace(c) != 0;
    }).base();
    if (first >= last) {
        return {};
    }
    return std::string(first, last);
}

std::string FileFingerprint(const std::string& path) {
    if (path.empty()) {
        return "unknown";
    }
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return "unknown";
    }

    std::uint64_t hash = 1469598103934665603ull;
    for (char c : path) {
        hash ^= static_cast<unsigned char>(c);
        hash *= 1099511628211ull;
    }
    file.seekg(0, std::ios::end);
    const auto size = file.tellg();
    for (char c : std::to_string(static_cast<long long>(size))) {
        hash ^= static_cast<unsigned char>(c);
        hash *= 1099511628211ull;
    }

    std::ostringstream out;
    out << "fast-fnv1a64:" << std::hex << std::setw(16) << std::setfill('0') << hash;
    return out.str();
}

std::string SigningStateForPath(const std::string& path) {
    return path.empty() ? "unknown" : "unverified";
}

std::string ReadPromptLine(const std::string& prompt) {
#ifndef _WIN32
    termios previous{};
    const bool hasPrevious = tcgetattr(STDIN_FILENO, &previous) == 0;
    if (hasPrevious) {
        termios cooked = previous;
        cooked.c_lflag |= (ICANON | ECHO);
        cooked.c_cc[VMIN] = 1;
        cooked.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSANOW, &cooked);
    }
#endif

    std::cout << "\x1b[?25h\n\n" << prompt;
    std::cout.flush();

    std::string input;
    std::getline(std::cin, input);

#ifndef _WIN32
    if (hasPrevious) {
        tcsetattr(STDIN_FILENO, TCSANOW, &previous);
    }
#endif
    return TrimCopy(input);
}

class IntegrationHub {
public:
    void publish(EventType type, DWORD pid, const std::string& text) {
        events_.push_back({ nextSequence_++, type, pid, text, UnixTimeMs() });
        if (events_.size() > 500) {
            events_.erase(events_.begin());
        }
    }

    const std::vector<ActionEvent>& events() const {
        return events_;
    }

private:
    std::vector<ActionEvent> events_;
    std::size_t nextSequence_ = 1;
};

#ifdef _WIN32
class ProcessCollector {
public:
    ProcessSnapshot collect(const AppOptions& options) {
        const unsigned long long systemTicks = currentSystemTicks();
        const auto serviceMap = buildServiceMap();
        ProcessSnapshot snapshot;
        std::map<DWORD, ProcessTimes> currentTimes;

        HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshotHandle == INVALID_HANDLE_VALUE) {
            return snapshot;
        }

        PROCESSENTRY32 entry{};
        entry.dwSize = sizeof(entry);
        if (Process32First(snapshotHandle, &entry)) {
            do {
                ProcessInfo info;
                info.pid = entry.th32ProcessID;
                info.parentPid = entry.th32ParentProcessID;
                info.threads = entry.cntThreads;
                info.name = WideToUtf8(entry.szExeFile);
                info.path = queryImagePath(info.pid);
                info.commandLine = info.path.value.empty() ? info.name : info.path.value;
                info.hash = FileFingerprint(info.path.value);
                info.signer = SigningStateForPath(info.path.value);
                info.sid = querySid(info.pid);
                info.workingSet = queryWorkingSet(info.pid);

                const auto service = serviceMap.find(info.pid);
                if (service != serviceMap.end()) {
                    info.service = service->second;
                }

                const unsigned long long processTicks = queryProcessTicks(info.pid);
                currentTimes[info.pid] = { processTicks, systemTicks };

                const auto old = previousTimes_.find(info.pid);
                if (old != previousTimes_.end() && systemTicks > old->second.systemTicks && processTicks >= old->second.processTicks) {
                    const auto processDelta = processTicks - old->second.processTicks;
                    const auto systemDelta = systemTicks - old->second.systemTicks;
                    info.cpu = (static_cast<double>(processDelta) / static_cast<double>(systemDelta)) * 100.0;
                }

                snapshot.processes.push_back(std::move(info));
            } while (Process32Next(snapshotHandle, &entry));
        }

        CloseHandle(snapshotHandle);
        previousTimes_ = std::move(currentTimes);
        snapshot.services = collectServices();
        snapshot.drivers = collectDrivers();
        snapshot.registryKeys = collectRegistryKeys();

        std::sort(snapshot.processes.begin(), snapshot.processes.end(), [&](const ProcessInfo& left, const ProcessInfo& right) {
            return ComesBefore(left, right, options.sortMode);
        });

        return snapshot;
    }

private:
    static unsigned long long currentSystemTicks() {
        FILETIME idle{}, kernel{}, user{};
        if (!GetSystemTimes(&idle, &kernel, &user)) {
            return 0;
        }
        return FileTimeToTicks(kernel) + FileTimeToTicks(user);
    }

    static AccessField queryImagePath(DWORD pid) {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process) {
            return { {}, FormatLastError() };
        }

        char buffer[MAX_PATH * 4]{};
        DWORD size = static_cast<DWORD>(std::size(buffer));
        AccessField result;
        if (QueryFullProcessImageNameA(process, 0, buffer, &size)) {
            result.value.assign(buffer, size);
        } else {
            result.status = FormatLastError();
        }

        CloseHandle(process);
        return result;
    }

    static AccessField querySid(DWORD pid) {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process) {
            return { {}, FormatLastError() };
        }

        HANDLE token = nullptr;
        if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
            AccessField result{ {}, FormatLastError() };
            CloseHandle(process);
            return result;
        }

        DWORD needed = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
        std::vector<BYTE> buffer(needed);
        AccessField result;
        if (needed != 0 && GetTokenInformation(token, TokenUser, buffer.data(), needed, &needed)) {
            TOKEN_USER* user = reinterpret_cast<TOKEN_USER*>(buffer.data());
            LPSTR converted = nullptr;
            if (ConvertSidToStringSidA(user->User.Sid, &converted)) {
                result.value = converted;
                LocalFree(converted);
            } else {
                result.status = FormatLastError();
            }
        } else {
            result.status = FormatLastError();
        }

        CloseHandle(token);
        CloseHandle(process);
        return result;
    }

    static SIZE_T queryWorkingSet(DWORD pid) {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!process) {
            return 0;
        }

        PROCESS_MEMORY_COUNTERS counters{};
        SIZE_T workingSet = 0;
        if (GetProcessMemoryInfo(process, &counters, sizeof(counters))) {
            workingSet = counters.WorkingSetSize;
        }
        CloseHandle(process);
        return workingSet;
    }

    static unsigned long long queryProcessTicks(DWORD pid) {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process) {
            return 0;
        }

        FILETIME created{}, exited{}, kernel{}, user{};
        unsigned long long ticks = 0;
        if (GetProcessTimes(process, &created, &exited, &kernel, &user)) {
            ticks = FileTimeToTicks(kernel) + FileTimeToTicks(user);
        }
        CloseHandle(process);
        return ticks;
    }

    static std::unordered_map<DWORD, std::string> buildServiceMap() {
        std::unordered_map<DWORD, std::string> servicesByPid;
        SC_HANDLE manager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
        if (!manager) {
            return servicesByPid;
        }

        DWORD bytesNeeded = 0;
        DWORD serviceCount = 0;
        DWORD resume = 0;
        EnumServicesStatusExA(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, nullptr, 0, &bytesNeeded, &serviceCount, &resume, nullptr);
        if (bytesNeeded == 0) {
            CloseServiceHandle(manager);
            return servicesByPid;
        }

        std::vector<BYTE> buffer(bytesNeeded + 4096);
        resume = 0;
        if (EnumServicesStatusExA(
                manager,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &bytesNeeded,
                &serviceCount,
                &resume,
                nullptr)) {
            auto* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSA*>(buffer.data());
            for (DWORD i = 0; i < serviceCount; ++i) {
                const DWORD pid = services[i].ServiceStatusProcess.dwProcessId;
                if (pid == 0) {
                    continue;
                }
                auto& value = servicesByPid[pid];
                if (!value.empty()) {
                    value += ",";
                }
                value += services[i].lpServiceName;
            }
        }

        CloseServiceHandle(manager);
        return servicesByPid;
    }

    static std::vector<SystemEntry> collectServices() {
        std::vector<SystemEntry> result;
        SC_HANDLE manager = OpenSCManager(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
        if (!manager) {
            result.push_back({ "service", "<access denied>", FormatLastError(), 0 });
            return result;
        }

        DWORD bytesNeeded = 0;
        DWORD serviceCount = 0;
        DWORD resume = 0;
        EnumServicesStatusExA(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, nullptr, 0, &bytesNeeded, &serviceCount, &resume, nullptr);
        if (bytesNeeded != 0) {
            std::vector<BYTE> buffer(bytesNeeded + 4096);
            resume = 0;
            if (EnumServicesStatusExA(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesNeeded, &serviceCount, &resume, nullptr)) {
                auto* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSA*>(buffer.data());
                for (DWORD i = 0; i < serviceCount; ++i) {
                    const DWORD state = services[i].ServiceStatusProcess.dwCurrentState;
                    const std::string stateText = state == SERVICE_RUNNING ? "running" : (state == SERVICE_STOPPED ? "stopped" : "state " + std::to_string(state));
                    result.push_back({ "service", services[i].lpServiceName ? services[i].lpServiceName : "", stateText, services[i].ServiceStatusProcess.dwProcessId });
                }
            }
        }

        CloseServiceHandle(manager);
        std::sort(result.begin(), result.end(), [](const SystemEntry& left, const SystemEntry& right) {
            return ToLower(left.name) < ToLower(right.name);
        });
        return result;
    }

    static std::vector<SystemEntry> collectDrivers() {
        std::vector<SystemEntry> result;
        std::vector<LPVOID> drivers(1024);
        DWORD needed = 0;
        if (!EnumDeviceDrivers(drivers.data(), static_cast<DWORD>(drivers.size() * sizeof(LPVOID)), &needed)) {
            result.push_back({ "driver", "<access denied>", FormatLastError(), 0 });
            return result;
        }

        const DWORD count = std::min<DWORD>(needed / sizeof(LPVOID), static_cast<DWORD>(drivers.size()));
        for (DWORD i = 0; i < count; ++i) {
            char name[MAX_PATH]{};
            char path[MAX_PATH * 2]{};
            GetDeviceDriverBaseNameA(drivers[i], name, static_cast<DWORD>(std::size(name)));
            GetDeviceDriverFileNameA(drivers[i], path, static_cast<DWORD>(std::size(path)));
            const std::string driverPath = path;
            result.push_back({ "driver", name[0] ? name : "<unknown>", driverPath, 0, SigningStateForPath(driverPath), FileFingerprint(driverPath) });
        }
        return result;
    }

    static void appendRegistryRunKey(std::vector<SystemEntry>& result, HKEY root, const char* rootName, const char* path) {
        HKEY key = nullptr;
        if (RegOpenKeyExA(root, path, 0, KEY_READ, &key) != ERROR_SUCCESS) {
            return;
        }

        char valueName[512]{};
        BYTE data[2048]{};
        for (DWORD index = 0;; ++index) {
            DWORD nameSize = static_cast<DWORD>(std::size(valueName));
            DWORD dataSize = static_cast<DWORD>(std::size(data));
            DWORD type = 0;
            const LONG status = RegEnumValueA(key, index, valueName, &nameSize, nullptr, &type, data, &dataSize);
            if (status == ERROR_NO_MORE_ITEMS) {
                break;
            }
            if (status == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ)) {
                std::string detail(reinterpret_cast<const char*>(data), strnlen_s(reinterpret_cast<const char*>(data), dataSize));
                result.push_back({ "registry", std::string(rootName) + "\\" + path + "\\" + valueName, detail, 0, "unknown", FileFingerprint(detail) });
            }
        }
        RegCloseKey(key);
    }

    static std::vector<SystemEntry> collectRegistryKeys() {
        std::vector<SystemEntry> result;
        appendRegistryRunKey(result, HKEY_CURRENT_USER, "HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
        appendRegistryRunKey(result, HKEY_LOCAL_MACHINE, "HKLM", "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
        appendRegistryRunKey(result, HKEY_LOCAL_MACHINE, "HKLM", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
        return result;
    }

    std::map<DWORD, ProcessTimes> previousTimes_;
};
#else
class ProcessCollector {
public:
    ProcessSnapshot collect(const AppOptions& options) {
        const unsigned long long systemTicks = currentSystemTicks();
        ProcessSnapshot snapshot;
        std::map<DWORD, ProcessTimes> currentTimes;

        DIR* proc = opendir("/proc");
        if (!proc) {
            return snapshot;
        }

        while (dirent* entry = readdir(proc)) {
            if (!isNumeric(entry->d_name)) {
                continue;
            }
            ProcessInfo info;
            info.pid = static_cast<DWORD>(std::strtoul(entry->d_name, nullptr, 10));
            if (!readProcess(info, systemTicks, currentTimes)) {
                continue;
            }
            snapshot.processes.push_back(std::move(info));
        }
        closedir(proc);

        previousTimes_ = std::move(currentTimes);
        snapshot.services = collectServices();
        snapshot.drivers = collectDrivers();
        snapshot.registryKeys = collectRegistryKeys();

        std::sort(snapshot.processes.begin(), snapshot.processes.end(), [&](const ProcessInfo& left, const ProcessInfo& right) {
            return ComesBefore(left, right, options.sortMode);
        });
        return snapshot;
    }

private:
    static bool isNumeric(const char* text) {
        if (!text || !*text) {
            return false;
        }
        for (const char* p = text; *p; ++p) {
            if (!std::isdigit(static_cast<unsigned char>(*p))) {
                return false;
            }
        }
        return true;
    }

    static std::string readFile(const std::string& path) {
        std::ifstream file(path);
        if (!file) {
            return {};
        }
        std::ostringstream out;
        out << file.rdbuf();
        return out.str();
    }

    static std::string readFirstLine(const std::string& path) {
        std::ifstream file(path);
        std::string line;
        std::getline(file, line);
        return line;
    }

    static AccessField readLinkField(const std::string& path) {
        std::vector<char> buffer(4096);
        const ssize_t size = readlink(path.c_str(), buffer.data(), buffer.size() - 1);
        if (size < 0) {
            return { {}, FormatLastError(errno) };
        }
        return { std::string(buffer.data(), static_cast<std::size_t>(size)), {} };
    }

    static unsigned long long currentSystemTicks() {
        std::ifstream file("/proc/stat");
        std::string label;
        unsigned long long total = 0;
        file >> label;
        for (unsigned long long value = 0; file >> value;) {
            total += value;
        }
        return total;
    }

    bool readProcess(ProcessInfo& info, unsigned long long systemTicks, std::map<DWORD, ProcessTimes>& currentTimes) {
        const std::string base = "/proc/" + std::to_string(info.pid);
        const std::string stat = readFile(base + "/stat");
        const auto open = stat.find('(');
        const auto close = stat.rfind(')');
        if (open == std::string::npos || close == std::string::npos || close <= open) {
            return false;
        }

        info.name = stat.substr(open + 1, close - open - 1);
        std::istringstream tail(stat.substr(close + 2));
        std::vector<std::string> fields;
        for (std::string field; tail >> field;) {
            fields.push_back(field);
        }
        if (fields.size() < 22) {
            return false;
        }

        info.parentPid = static_cast<DWORD>(std::strtoul(fields[1].c_str(), nullptr, 10));
        const unsigned long long utime = std::strtoull(fields[11].c_str(), nullptr, 10);
        const unsigned long long stime = std::strtoull(fields[12].c_str(), nullptr, 10);
        const unsigned long long processTicks = utime + stime;
        currentTimes[info.pid] = { processTicks, systemTicks };

        const auto old = previousTimes_.find(info.pid);
        if (old != previousTimes_.end() && systemTicks > old->second.systemTicks && processTicks >= old->second.processTicks) {
            info.cpu = (static_cast<double>(processTicks - old->second.processTicks) / static_cast<double>(systemTicks - old->second.systemTicks)) * 100.0;
        }

        readStatus(info, base + "/status");
        info.path = readLinkField(base + "/exe");
        info.commandLine = readCommandLine(base + "/cmdline");
        info.hash = FileFingerprint(info.path.value);
        info.signer = SigningStateForPath(info.path.value);
        info.workingSet = readWorkingSet(base + "/statm");
        return true;
    }

    static std::string readCommandLine(const std::string& path) {
        std::string value = readFile(path);
        for (char& c : value) {
            if (c == '\0') {
                c = ' ';
            }
        }
        return TrimCopy(value);
    }

    static void readStatus(ProcessInfo& info, const std::string& path) {
        std::ifstream file(path);
        for (std::string line; std::getline(file, line);) {
            if (line.rfind("Threads:", 0) == 0) {
                info.threads = static_cast<DWORD>(std::strtoul(line.substr(8).c_str(), nullptr, 10));
            } else if (line.rfind("Uid:", 0) == 0) {
                std::istringstream parser(line.substr(4));
                std::string uid;
                parser >> uid;
                info.sid = { "uid:" + uid, {} };
            }
        }
    }

    static SIZE_T readWorkingSet(const std::string& path) {
        std::ifstream file(path);
        unsigned long pages = 0;
        unsigned long rss = 0;
        file >> pages >> rss;
        return static_cast<SIZE_T>(rss) * static_cast<SIZE_T>(sysconf(_SC_PAGESIZE));
    }

    static std::vector<SystemEntry> collectServices() {
        std::vector<SystemEntry> result;
        collectSystemdUnits(result, "/etc/systemd/system");
        collectSystemdUnits(result, "/lib/systemd/system");
        collectSystemdUnits(result, "/usr/lib/systemd/system");
        std::sort(result.begin(), result.end(), [](const SystemEntry& left, const SystemEntry& right) {
            return ToLower(left.name) < ToLower(right.name);
        });
        return result;
    }

    static void collectSystemdUnits(std::vector<SystemEntry>& result, const std::string& directory) {
        DIR* dir = opendir(directory.c_str());
        if (!dir) {
            return;
        }
        while (dirent* entry = readdir(dir)) {
            std::string name = entry->d_name;
            if (name.size() > 8 && name.substr(name.size() - 8) == ".service") {
                result.push_back({ "service", name, directory + "/" + name, 0 });
            }
        }
        closedir(dir);
    }

    static std::vector<SystemEntry> collectDrivers() {
        std::vector<SystemEntry> result;
        std::ifstream file("/proc/modules");
        for (std::string line; std::getline(file, line);) {
            std::istringstream parser(line);
            std::string name;
            std::string size;
            parser >> name >> size;
            if (!name.empty()) {
                result.push_back({ "driver", name, "module size " + size, 0, "unknown", "unknown" });
            }
        }
        return result;
    }

    static std::vector<SystemEntry> collectRegistryKeys() {
        std::vector<SystemEntry> result;
        collectStartupLinks(result, "/etc/systemd/system/multi-user.target.wants");
        collectStartupLinks(result, "/etc/systemd/system/graphical.target.wants");
        collectStartupLinks(result, "/etc/systemd/system/default.target.wants");
        collectStartupLinks(result, "/lib/systemd/system/multi-user.target.wants");
        collectStartupLinks(result, "/usr/lib/systemd/system/multi-user.target.wants");
        collectDesktopAutostart(result, "/etc/xdg/autostart");

        const char* home = std::getenv("HOME");
        if (home && *home) {
            collectDesktopAutostart(result, std::string(home) + "/.config/autostart");
        }

        std::sort(result.begin(), result.end(), [](const SystemEntry& left, const SystemEntry& right) {
            return ToLower(left.name) < ToLower(right.name);
        });
        return result;
    }

    static void collectStartupLinks(std::vector<SystemEntry>& result, const std::string& directory) {
        DIR* dir = opendir(directory.c_str());
        if (!dir) {
            return;
        }

        while (dirent* entry = readdir(dir)) {
            const std::string name = entry->d_name;
            if (name == "." || name == "..") {
                continue;
            }
            AccessField target = readLinkField(directory + "/" + name);
            const std::string targetPath = target.ok() ? target.value : directory + "/" + name;
            result.push_back({ "startup", name, targetPath, 0, SigningStateForPath(targetPath), FileFingerprint(targetPath) });
        }
        closedir(dir);
    }

    static void collectDesktopAutostart(std::vector<SystemEntry>& result, const std::string& directory) {
        DIR* dir = opendir(directory.c_str());
        if (!dir) {
            return;
        }

        while (dirent* entry = readdir(dir)) {
            const std::string name = entry->d_name;
            if (name.size() > 8 && name.substr(name.size() - 8) == ".desktop") {
                const std::string path = directory + "/" + name;
                result.push_back({ "startup", name, path, 0, SigningStateForPath(path), FileFingerprint(path) });
            }
        }
        closedir(dir);
    }

    std::map<DWORD, ProcessTimes> previousTimes_;
};
#endif

class ProcessRepository {
public:
    ProcessSnapshot refresh(const AppOptions& options, bool paused) {
        if (!paused) {
            previous_ = current_;
            current_ = collector_.collect(options);
        }
        return current_;
    }

    const ProcessSnapshot& current() const {
        return current_;
    }

    const ProcessSnapshot& previous() const {
        return previous_;
    }

private:
    ProcessCollector collector_;
    ProcessSnapshot current_;
    ProcessSnapshot previous_;
};

std::string HistoryKindName(HistoryKind kind) {
    switch (kind) {
    case HistoryKind::Process: return "process";
    case HistoryKind::Service: return "service";
    case HistoryKind::Startup: return StartupAreaName();
    case HistoryKind::Driver: return "driver";
    }
    return "process";
}

class HistoryTracker {
public:
    void update(const ProcessSnapshot& previous, const ProcessSnapshot& current, IntegrationHub& hub) {
        if (!seeded_) {
            seeded_ = true;
            return;
        }
        updateProcesses(previous.processes, current.processes, hub);
        updateSystemEntries(HistoryKind::Service, previous.services, current.services);
        updateSystemEntries(HistoryKind::Startup, previous.registryKeys, current.registryKeys);
        updateSystemEntries(HistoryKind::Driver, previous.drivers, current.drivers);
    }

    const std::vector<HistoryEvent>& events() const {
        return events_;
    }

    std::vector<HistoryEvent> eventsFor(HistoryKind kind) const {
        std::vector<HistoryEvent> result;
        for (const auto& event : events_) {
            if (event.kind == kind) {
                result.push_back(event);
            }
        }
        return result;
    }

    int countFor(HistoryKind kind) const {
        int total = 0;
        for (const auto& event : events_) {
            total += event.kind == kind ? 1 : 0;
        }
        return total;
    }

private:
    struct SystemState {
        std::string name;
        std::string detail;
        DWORD pid = 0;
        std::string signer;
        std::string hash;
    };

    void updateProcesses(const std::vector<ProcessInfo>& previous, const std::vector<ProcessInfo>& current, IntegrationHub& hub) {
        std::unordered_map<DWORD, ProcessInfo> oldByPid;
        std::unordered_map<DWORD, ProcessInfo> newByPid;
        for (const auto& process : previous) {
            oldByPid[process.pid] = process;
        }
        for (const auto& process : current) {
            newByPid[process.pid] = process;
        }

        for (const auto& item : newByPid) {
            if (oldByPid.count(item.first) == 0) {
                add(HistoryKind::Process, "started", std::to_string(item.first), item.second.name, item.second.commandLine, item.first);
                hub.publish(EventType::ViewChanged, item.first, "process started: " + item.second.name);
            }
        }
        for (const auto& item : oldByPid) {
            if (newByPid.count(item.first) == 0) {
                add(HistoryKind::Process, "stopped", std::to_string(item.first), item.second.name, item.second.commandLine, item.first);
                hub.publish(EventType::ViewChanged, item.first, "process stopped: " + item.second.name);
            }
        }
    }

    void updateSystemEntries(HistoryKind kind, const std::vector<SystemEntry>& previous, const std::vector<SystemEntry>& current) {
        const auto oldItems = indexSystem(previous);
        const auto newItems = indexSystem(current);
        for (const auto& item : newItems) {
            const auto old = oldItems.find(item.first);
            if (old == oldItems.end()) {
                add(kind, "added", item.first, item.second.name, item.second.detail, item.second.pid);
            } else if (old->second.detail != item.second.detail || old->second.pid != item.second.pid || old->second.signer != item.second.signer || old->second.hash != item.second.hash) {
                add(kind, "changed", item.first, item.second.name, item.second.detail, item.second.pid);
            }
        }
        for (const auto& item : oldItems) {
            if (newItems.count(item.first) == 0) {
                add(kind, "removed", item.first, item.second.name, item.second.detail, item.second.pid);
            }
        }
    }

    static std::unordered_map<std::string, SystemState> indexSystem(const std::vector<SystemEntry>& entries) {
        std::unordered_map<std::string, SystemState> result;
        for (const auto& entry : entries) {
            result[entry.type + ":" + entry.name] = { entry.name, entry.detail, entry.pid, entry.signer, entry.hash };
        }
        return result;
    }

    void add(HistoryKind kind, const std::string& action, const std::string& key, const std::string& name, const std::string& detail, DWORD pid) {
        events_.push_back({ nextSequence_++, kind, action, key, name, detail, pid, UnixTimeMs() });
        if (events_.size() > 1000) {
            events_.erase(events_.begin(), events_.begin() + static_cast<std::ptrdiff_t>(events_.size() - 1000));
        }
    }

    std::vector<HistoryEvent> events_;
    std::size_t nextSequence_ = 1;
    bool seeded_ = false;
};

class HuntService {
public:
    void update(UiState& ui, const std::vector<ProcessInfo>& processes, IntegrationHub& hub) {
        if (!ui.hunt.active) {
            return;
        }

        const ProcessInfo* target = findByPid(processes, ui.hunt.pid);
        if (!target) {
            for (const auto& process : processes) {
                if (!ui.hunt.name.empty() && ToLower(process.name) == ToLower(ui.hunt.name)) {
                    target = &process;
                    ui.hunt.pid = process.pid;
                    ui.hunt.status = "reacquired PID " + std::to_string(process.pid);
                    break;
                }
            }
        }

        if (!target) {
            ui.hunt.missingFrames += 1;
            setAlert(ui, hub, "target missing");
            return;
        }

        ui.hunt.missingFrames = 0;
        if (ui.hunt.name.empty()) {
            ui.hunt.name = target->name;
        }

        std::vector<std::string> alerts;
        if (target->cpu >= ui.hunt.cpuAlert) {
            alerts.push_back("cpu spike");
        }

        if (ui.hunt.lastWorkingSet != 0 && target->workingSet > ui.hunt.lastWorkingSet + ui.hunt.memoryJumpAlert) {
            alerts.push_back("memory jump");
        }

        ui.hunt.lastCpu = target->cpu;
        ui.hunt.peakCpu = std::max(ui.hunt.peakCpu, target->cpu);
        ui.hunt.lastWorkingSet = target->workingSet;
        ui.hunt.peakWorkingSet = std::max(ui.hunt.peakWorkingSet, target->workingSet);
        ui.hunt.status = "watching PID " + std::to_string(target->pid);
        setAlert(ui, hub, joinAlerts(alerts));
    }

private:
    static const ProcessInfo* findByPid(const std::vector<ProcessInfo>& processes, DWORD pid) {
        for (const auto& process : processes) {
            if (process.pid == pid) {
                return &process;
            }
        }
        return nullptr;
    }

    static std::string joinAlerts(const std::vector<std::string>& alerts) {
        std::string result;
        for (const auto& alert : alerts) {
            if (!result.empty()) {
                result += " + ";
            }
            result += alert;
        }
        return result;
    }

    void setAlert(UiState& ui, IntegrationHub& hub, const std::string& alert) {
        const bool changed = ui.hunt.alert != alert;
        ui.hunt.alert = alert;
        if (changed && !alert.empty()) {
            hub.publish(EventType::HuntAlertTriggered, ui.hunt.pid, alert);
            ui.notify(NotificationKind::Warning, "hunt: " + alert);
        }
    }
};

struct AlertRule {
    std::string name;
    std::string field;
    std::string op;
    std::string value;
    double number = 0.0;
};

class AlertRuleService {
public:
    bool load(const std::string& path, std::string& error) {
        rules_.clear();
        std::ifstream file(path);
        if (!file) {
            error = "unable to open rules file";
            return false;
        }

        std::ostringstream content;
        content << file.rdbuf();
        const std::string text = content.str();
        const std::string lowerPath = ToLower(path);
        bool ok = false;
        if (lowerPath.size() >= 5 && lowerPath.substr(lowerPath.size() - 5) == ".json") {
            ok = loadJsonRules(text, error);
        } else if (lowerPath.size() >= 5 && lowerPath.substr(lowerPath.size() - 5) == ".toml") {
            ok = loadTomlRules(text, error);
        } else if ((lowerPath.size() >= 5 && lowerPath.substr(lowerPath.size() - 5) == ".yaml") ||
                   (lowerPath.size() >= 4 && lowerPath.substr(lowerPath.size() - 4) == ".yml")) {
            ok = loadYamlRules(text, error);
        } else {
            ok = loadLineRules(text, error);
        }
        if (ok && rules_.empty()) {
            error = "no valid rules found";
            return false;
        }
        return ok;
    }

    bool loadLineRules(const std::string& text, std::string& error) {
        std::string line;
        int lineNo = 0;
        std::istringstream lines(text);
        while (std::getline(lines, line)) {
            lineNo += 1;
            const auto comment = line.find('#');
            if (comment != std::string::npos) {
                line = line.substr(0, comment);
            }
            std::istringstream parser(line);
            AlertRule rule;
            if (!(parser >> rule.name >> rule.field >> rule.op >> rule.value)) {
                continue;
            }
            if (!appendRule(rule, "line " + std::to_string(lineNo), error)) {
                return false;
            }
        }
        return true;
    }

    void evaluate(const ProcessSnapshot& snapshot, UiState& ui, IntegrationHub& hub) {
        std::unordered_map<DWORD, int> childCounts;
        for (const auto& process : snapshot.processes) {
            if (process.pid != process.parentPid) {
                childCounts[process.parentPid] += 1;
            }
        }

        for (auto& item : cooldown_) {
            if (item.second > 0) {
                item.second -= 1;
            }
        }

        int fired = 0;
        for (const auto& process : snapshot.processes) {
            for (const auto& rule : rules_) {
                const auto childCount = childCounts.find(process.pid);
                if (!matches(rule, process, childCount == childCounts.end() ? 0 : childCount->second)) {
                    continue;
                }
                const std::string key = rule.name + ":" + std::to_string(process.pid);
                if (cooldown_[key] > 0) {
                    continue;
                }
                cooldown_[key] = 30;
                fired += 1;
                hub.publish(EventType::RuleAlertTriggered, process.pid, rule.name + " matched " + process.name);
                if (fired == 1) {
                    ui.notify(NotificationKind::Warning, "rule alert: " + rule.name + " PID " + std::to_string(process.pid), 50);
                }
            }
        }
    }

    const std::vector<AlertRule>& rules() const {
        return rules_;
    }

private:
    static std::string stripQuotes(std::string value) {
        value = TrimCopy(value);
        if (value.size() >= 2 && ((value.front() == '"' && value.back() == '"') || (value.front() == '\'' && value.back() == '\''))) {
            return value.substr(1, value.size() - 2);
        }
        return value;
    }

    bool appendRule(AlertRule rule, const std::string& source, std::string& error) {
        rule.name = stripQuotes(rule.name);
        rule.field = ToLower(stripQuotes(rule.field));
        rule.op = ToLower(stripQuotes(rule.op));
        rule.value = stripQuotes(rule.value);
        rule.number = std::strtod(rule.value.c_str(), nullptr);
        if (!validRule(rule)) {
            error = "invalid rule at " + source;
            return false;
        }
        rules_.push_back(std::move(rule));
        return true;
    }

    bool loadJsonRules(const std::string& text, std::string& error) {
        std::size_t pos = 0;
        int index = 0;
        while ((pos = text.find('{', pos)) != std::string::npos) {
            const std::size_t end = text.find('}', pos + 1);
            if (end == std::string::npos) {
                error = "unterminated JSON rule object";
                return false;
            }
            const std::string object = text.substr(pos + 1, end - pos - 1);
            AlertRule rule;
            rule.name = jsonField(object, "name");
            rule.field = jsonField(object, "field");
            rule.op = jsonField(object, "op");
            rule.value = jsonField(object, "value");
            pos = end + 1;
            if (rule.name.empty() && rule.field.empty() && rule.op.empty() && rule.value.empty()) {
                continue;
            }
            index += 1;
            if (!appendRule(rule, "json rule " + std::to_string(index), error)) {
                return false;
            }
        }
        return true;
    }

    bool loadTomlRules(const std::string& text, std::string& error) {
        AlertRule current;
        bool inRule = false;
        int index = 0;
        std::istringstream lines(text);
        for (std::string line; std::getline(lines, line);) {
            const auto comment = line.find('#');
            if (comment != std::string::npos) {
                line = line.substr(0, comment);
            }
            line = TrimCopy(line);
            if (line.empty()) {
                continue;
            }
            if (line == "[[rules]]") {
                if (inRule) {
                    index += 1;
                    if (!appendRule(current, "toml rule " + std::to_string(index), error)) {
                        return false;
                    }
                    current = AlertRule{};
                }
                inRule = true;
                continue;
            }
            if (inRule) {
                assignKeyValue(current, line, '=');
            }
        }
        if (inRule) {
            index += 1;
            return appendRule(current, "toml rule " + std::to_string(index), error);
        }
        return true;
    }

    bool loadYamlRules(const std::string& text, std::string& error) {
        AlertRule current;
        bool inRule = false;
        int index = 0;
        std::istringstream lines(text);
        for (std::string line; std::getline(lines, line);) {
            const auto comment = line.find('#');
            if (comment != std::string::npos) {
                line = line.substr(0, comment);
            }
            line = TrimCopy(line);
            if (line.empty() || line == "rules:") {
                continue;
            }
            if (line.rfind("- ", 0) == 0) {
                if (inRule) {
                    index += 1;
                    if (!appendRule(current, "yaml rule " + std::to_string(index), error)) {
                        return false;
                    }
                    current = AlertRule{};
                }
                inRule = true;
                line = TrimCopy(line.substr(2));
                if (!line.empty()) {
                    assignKeyValue(current, line, ':');
                }
                continue;
            }
            if (inRule) {
                assignKeyValue(current, line, ':');
            }
        }
        if (inRule) {
            index += 1;
            return appendRule(current, "yaml rule " + std::to_string(index), error);
        }
        return true;
    }

    static std::string jsonField(const std::string& object, const std::string& key) {
        const std::string quotedKey = "\"" + key + "\"";
        std::size_t pos = object.find(quotedKey);
        if (pos == std::string::npos) {
            return {};
        }
        pos = object.find(':', pos + quotedKey.size());
        if (pos == std::string::npos) {
            return {};
        }
        pos += 1;
        while (pos < object.size() && std::isspace(static_cast<unsigned char>(object[pos])) != 0) {
            pos += 1;
        }
        if (pos < object.size() && object[pos] == '"') {
            std::size_t end = pos + 1;
            while (end < object.size()) {
                if (object[end] == '"' && object[end - 1] != '\\') {
                    break;
                }
                end += 1;
            }
            return end < object.size() ? object.substr(pos + 1, end - pos - 1) : std::string();
        }
        const std::size_t end = object.find_first_of(",\r\n", pos);
        return TrimCopy(object.substr(pos, end == std::string::npos ? std::string::npos : end - pos));
    }

    static void assignKeyValue(AlertRule& rule, const std::string& line, char delimiter) {
        const std::size_t split = line.find(delimiter);
        if (split == std::string::npos) {
            return;
        }
        const std::string key = ToLower(TrimCopy(line.substr(0, split)));
        const std::string value = stripQuotes(line.substr(split + 1));
        if (key == "name") rule.name = value;
        if (key == "field") rule.field = value;
        if (key == "op") rule.op = value;
        if (key == "value") rule.value = value;
    }

    static bool validRule(const AlertRule& rule) {
        const bool numeric = rule.op == "gt" || rule.op == "gte" || rule.op == "lt" || rule.op == "lte" || rule.op == "eq";
        const bool text = rule.op == "contains" || rule.op == "eq";
        const bool knownField = rule.field == "cpu" || rule.field == "mem_mb" || rule.field == "threads" || rule.field == "pid" || rule.field == "ppid" ||
            rule.field == "child_count" || rule.field == "name" || rule.field == "path" || rule.field == "command_line" || rule.field == "cmdline" ||
            rule.field == "service" || rule.field == "sid" || rule.field == "signer" || rule.field == "hash";
        return knownField && (numeric || text);
    }

    static std::string fieldText(const AlertRule& rule, const ProcessInfo& process, int childCount) {
        if (rule.field == "name") return process.name;
        if (rule.field == "path") return process.path.value;
        if (rule.field == "command_line" || rule.field == "cmdline") return process.commandLine;
        if (rule.field == "service") return process.service;
        if (rule.field == "sid") return process.sid.value;
        if (rule.field == "pid") return std::to_string(process.pid);
        if (rule.field == "ppid") return std::to_string(process.parentPid);
        if (rule.field == "threads") return std::to_string(process.threads);
        if (rule.field == "child_count") return std::to_string(childCount);
        if (rule.field == "cpu") return std::to_string(process.cpu);
        if (rule.field == "mem_mb") return MemoryMb(process.workingSet);
        if (rule.field == "signer") return process.signer;
        if (rule.field == "hash") return process.hash;
        return {};
    }

    static double fieldNumber(const AlertRule& rule, const ProcessInfo& process, int childCount) {
        if (rule.field == "cpu") return process.cpu;
        if (rule.field == "mem_mb") return static_cast<double>(process.workingSet) / 1024.0 / 1024.0;
        if (rule.field == "threads") return static_cast<double>(process.threads);
        if (rule.field == "pid") return static_cast<double>(process.pid);
        if (rule.field == "ppid") return static_cast<double>(process.parentPid);
        if (rule.field == "child_count") return static_cast<double>(childCount);
        return std::strtod(fieldText(rule, process, childCount).c_str(), nullptr);
    }

    static bool matches(const AlertRule& rule, const ProcessInfo& process, int childCount) {
        if (rule.op == "contains") {
            return ContainsText(fieldText(rule, process, childCount), rule.value);
        }
        if (rule.op == "eq") {
            if (rule.field == "name" || rule.field == "path" || rule.field == "command_line" || rule.field == "cmdline" ||
                rule.field == "service" || rule.field == "sid" || rule.field == "signer" || rule.field == "hash") {
                return ToLower(fieldText(rule, process, childCount)) == ToLower(rule.value);
            }
            return fieldNumber(rule, process, childCount) == rule.number;
        }
        const double value = fieldNumber(rule, process, childCount);
        if (rule.op == "gt") return value > rule.number;
        if (rule.op == "gte") return value >= rule.number;
        if (rule.op == "lt") return value < rule.number;
        if (rule.op == "lte") return value <= rule.number;
        return false;
    }

    std::vector<AlertRule> rules_;
    std::unordered_map<std::string, int> cooldown_;
};

class IntegrationExporter {
public:
    void writeEvents(const IntegrationHub& hub, const std::string& path) {
        if (path.empty()) {
            return;
        }
        std::ofstream file(path, std::ios::app);
        if (!file) {
            return;
        }
        for (const auto& event : hub.events()) {
            if (event.sequence <= lastEventSequence_) {
                continue;
            }
            file << "{\"ts\":" << event.timestampMs
                 << ",\"seq\":" << event.sequence
                 << ",\"type\":\"" << JsonEscape(EventTypeName(event.type)) << "\""
                 << ",\"pid\":" << event.pid
                 << ",\"message\":\"" << JsonEscape(event.text) << "\"}\n";
            lastEventSequence_ = event.sequence;
        }
    }

    static std::string eventsNdjson(const IntegrationHub& hub) {
        std::ostringstream out;
        for (const auto& event : hub.events()) {
            out << "{\"ts\":" << event.timestampMs
                << ",\"seq\":" << event.sequence
                << ",\"type\":\"" << JsonEscape(EventTypeName(event.type)) << "\""
                << ",\"pid\":" << event.pid
                << ",\"message\":\"" << JsonEscape(event.text) << "\"}\n";
        }
        return out.str();
    }

    static std::string prometheusText(const ProcessSnapshot& snapshot, const UiState& ui, const AlertRuleService& rules, const IntegrationHub& hub, const HistoryTracker* history = nullptr) {
        SIZE_T memory = 0;
        double cpu = 0.0;
        int kernel = 0;
        for (const auto& process : snapshot.processes) {
            memory += process.workingSet;
            cpu += process.cpu;
            kernel += IsKernelProcess(process) ? 1 : 0;
        }

        int ruleAlerts = 0;
        int huntAlerts = 0;
        for (const auto& event : hub.events()) {
            ruleAlerts += event.type == EventType::RuleAlertTriggered ? 1 : 0;
            huntAlerts += event.type == EventType::HuntAlertTriggered ? 1 : 0;
        }

        std::ostringstream out;
        out << "# HELP cliprocster_processes Number of visible collected processes\n"
            << "# TYPE cliprocster_processes gauge\n"
            << "cliprocster_processes " << snapshot.processes.size() << "\n"
            << "cliprocster_kernel_processes " << kernel << "\n"
            << "cliprocster_process_cpu_percent_sum " << std::fixed << std::setprecision(2) << cpu << "\n"
            << "cliprocster_process_working_set_bytes_sum " << memory << "\n"
            << "cliprocster_services " << snapshot.services.size() << "\n"
            << "cliprocster_kernel_drivers " << snapshot.drivers.size() << "\n"
            << "cliprocster_startup_entries " << snapshot.registryKeys.size() << "\n"
            << "cliprocster_hunt_active " << (ui.hunt.active ? 1 : 0) << "\n"
            << "cliprocster_hunt_alert " << (!ui.hunt.alert.empty() ? 1 : 0) << "\n"
            << "cliprocster_rules_loaded " << rules.rules().size() << "\n"
            << "cliprocster_rule_alerts_buffered_total " << ruleAlerts << "\n"
            << "cliprocster_hunt_alerts_buffered_total " << huntAlerts << "\n";
        if (history) {
            out << "cliprocster_history_process_events " << history->countFor(HistoryKind::Process) << "\n"
                << "cliprocster_history_service_events " << history->countFor(HistoryKind::Service) << "\n"
                << "cliprocster_history_startup_events " << history->countFor(HistoryKind::Startup) << "\n"
                << "cliprocster_history_driver_events " << history->countFor(HistoryKind::Driver) << "\n";
        }
        return out.str();
    }

    void writePrometheus(const ProcessSnapshot& snapshot, const UiState& ui, const AlertRuleService& rules, const IntegrationHub& hub, const std::string& path, const HistoryTracker* history = nullptr) {
        if (path.empty()) {
            return;
        }
        std::ofstream file(path, std::ios::trunc);
        if (!file) {
            return;
        }
        file << prometheusText(snapshot, ui, rules, hub, history);
    }

private:
    std::size_t lastEventSequence_ = 0;
};

class SnapshotExporter {
public:
    virtual ~SnapshotExporter() = default;
    virtual bool exportSnapshot(const SnapshotDto& snapshot, const std::string& path, std::string& error) = 0;
};

class JsonSnapshotExporter : public SnapshotExporter {
public:
    bool exportSnapshot(const SnapshotDto& snapshot, const std::string& path, std::string& error) override {
        std::ofstream file(path, std::ios::trunc);
        if (!file) {
            error = "unable to open output file";
            return false;
        }

        file << "{\n";
        file << "  \"view\": \"" << escape(snapshot.view) << "\",\n";
        file << "  \"filter\": \"" << escape(snapshot.filter) << "\",\n";
        file << "  \"selectedPid\": " << snapshot.selectedPid << ",\n";
        file << "  \"hunt\": { \"active\": " << (snapshot.huntActive ? "true" : "false")
             << ", \"pid\": " << snapshot.huntPid
             << ", \"alert\": \"" << escape(snapshot.huntAlert) << "\" },\n";
        file << "  \"processes\": [\n";
        for (std::size_t i = 0; i < snapshot.processes.size(); ++i) {
            const auto& process = snapshot.processes[i];
            file << "    {"
                 << "\"pid\": " << process.pid
                 << ", \"parentPid\": " << process.parentPid
                 << ", \"name\": \"" << escape(process.name) << "\""
                 << ", \"path\": \"" << escape(process.path) << "\""
                 << ", \"sid\": \"" << escape(process.sid) << "\""
                 << ", \"service\": \"" << escape(process.service) << "\""
                 << ", \"commandLine\": \"" << escape(process.commandLine) << "\""
                 << ", \"signer\": \"" << escape(process.signer) << "\""
                 << ", \"hash\": \"" << escape(process.hash) << "\""
                 << ", \"childCount\": " << process.childCount
                 << ", \"cpu\": " << std::fixed << std::setprecision(2) << process.cpu
                 << ", \"workingSet\": " << process.workingSet
                 << ", \"threads\": " << process.threads
                 << "}";
            file << (i + 1 == snapshot.processes.size() ? "\n" : ",\n");
        }
        file << "  ]\n";
        file << "}\n";

        if (!file) {
            error = "failed while writing JSON";
            return false;
        }
        return true;
    }

private:
    static std::string escape(const std::string& text) {
        std::ostringstream out;
        for (char c : text) {
            switch (c) {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                } else {
                    out << c;
                }
                break;
            }
        }
        return out.str();
    }
};

class SnapshotDtoFactory {
public:
    static SnapshotDto make(const ProcessSnapshot& snapshot, const AppOptions& options, const UiState& ui, const HistoryTracker* history = nullptr) {
        SnapshotDto dto;
        dto.selectedPid = ui.selectedPid;
        dto.view = ViewName(options.viewMode);
        dto.filter = options.filter;
        dto.huntActive = ui.hunt.active;
        dto.huntPid = ui.hunt.pid;
        dto.huntAlert = ui.hunt.alert;
        if (history) {
            dto.recentProcessEvents = history->countFor(HistoryKind::Process);
            dto.recentServiceEvents = history->countFor(HistoryKind::Service);
            dto.recentStartupEvents = history->countFor(HistoryKind::Startup);
            dto.recentDriverEvents = history->countFor(HistoryKind::Driver);
        }

        std::unordered_map<DWORD, int> childCounts;
        for (const auto& process : snapshot.processes) {
            if (process.pid != process.parentPid) {
                childCounts[process.parentPid] += 1;
            }
        }

        for (const auto& process : snapshot.processes) {
            ProcessDto item;
            item.pid = process.pid;
            item.parentPid = process.parentPid;
            item.name = process.name;
            item.path = process.path.value;
            item.sid = process.sid.value;
            item.service = process.service;
            item.commandLine = process.commandLine;
            item.signer = process.signer;
            item.hash = process.hash;
            item.childCount = childCounts[process.pid];
            item.cpu = process.cpu;
            item.workingSet = process.workingSet;
            item.threads = process.threads;
            dto.processes.push_back(std::move(item));
        }
        return dto;
    }
};

std::string SnapshotJson(const SnapshotDto& snapshot) {
    std::ostringstream out;
    out << "{\n";
    out << "  \"view\": \"" << JsonEscape(snapshot.view) << "\",\n";
    out << "  \"filter\": \"" << JsonEscape(snapshot.filter) << "\",\n";
    out << "  \"selectedPid\": " << snapshot.selectedPid << ",\n";
    out << "  \"hunt\": { \"active\": " << (snapshot.huntActive ? "true" : "false")
        << ", \"pid\": " << snapshot.huntPid
        << ", \"alert\": \"" << JsonEscape(snapshot.huntAlert) << "\" },\n";
    out << "  \"history\": { \"processes\": " << snapshot.recentProcessEvents
        << ", \"services\": " << snapshot.recentServiceEvents
        << ", \"startup\": " << snapshot.recentStartupEvents
        << ", \"drivers\": " << snapshot.recentDriverEvents << " },\n";
    out << "  \"processes\": [\n";
    for (std::size_t i = 0; i < snapshot.processes.size(); ++i) {
        const auto& process = snapshot.processes[i];
        out << "    {"
            << "\"pid\": " << process.pid
            << ", \"parentPid\": " << process.parentPid
            << ", \"name\": \"" << JsonEscape(process.name) << "\""
            << ", \"path\": \"" << JsonEscape(process.path) << "\""
            << ", \"sid\": \"" << JsonEscape(process.sid) << "\""
            << ", \"service\": \"" << JsonEscape(process.service) << "\""
            << ", \"commandLine\": \"" << JsonEscape(process.commandLine) << "\""
            << ", \"signer\": \"" << JsonEscape(process.signer) << "\""
            << ", \"hash\": \"" << JsonEscape(process.hash) << "\""
            << ", \"childCount\": " << process.childCount
            << ", \"cpu\": " << std::fixed << std::setprecision(2) << process.cpu
            << ", \"workingSet\": " << process.workingSet
            << ", \"threads\": " << process.threads
            << "}";
        out << (i + 1 == snapshot.processes.size() ? "\n" : ",\n");
    }
    out << "  ]\n";
    out << "}\n";
    return out.str();
}

std::string RulesJson(const AlertRuleService& rules) {
    std::ostringstream out;
    out << "{ \"rules\": [\n";
    const auto& loaded = rules.rules();
    for (std::size_t i = 0; i < loaded.size(); ++i) {
        const auto& rule = loaded[i];
        out << "  { \"name\": \"" << JsonEscape(rule.name) << "\", \"field\": \"" << JsonEscape(rule.field)
            << "\", \"op\": \"" << JsonEscape(rule.op) << "\", \"value\": \"" << JsonEscape(rule.value) << "\" }";
        out << (i + 1 == loaded.size() ? "\n" : ",\n");
    }
    out << "] }\n";
    return out.str();
}

std::string HistoryJson(const std::vector<HistoryEvent>& events) {
    std::ostringstream out;
    out << "{ \"events\": [\n";
    for (std::size_t i = 0; i < events.size(); ++i) {
        const auto& event = events[i];
        out << "  { \"seq\": " << event.sequence
            << ", \"ts\": " << event.timestampMs
            << ", \"kind\": \"" << JsonEscape(HistoryKindName(event.kind)) << "\""
            << ", \"action\": \"" << JsonEscape(event.action) << "\""
            << ", \"key\": \"" << JsonEscape(event.key) << "\""
            << ", \"name\": \"" << JsonEscape(event.name) << "\""
            << ", \"detail\": \"" << JsonEscape(event.detail) << "\""
            << ", \"pid\": " << event.pid << " }";
        out << (i + 1 == events.size() ? "\n" : ",\n");
    }
    out << "] }\n";
    return out.str();
}

struct ApiState {
    ProcessSnapshot snapshot;
    UiState ui;
    AppOptions options;
    std::string snapshotJson;
    std::string events;
    std::string metrics;
    std::string rules;
    std::string processHistory;
    std::string serviceHistory;
    std::string startupHistory;
    std::string driverHistory;
    std::string health;
    bool ready = false;
};

class LocalHttpApi {
public:
    ~LocalHttpApi() {
        stop();
    }

    bool start(const std::string& bindAddress, int port, std::string& error) {
        if (running_) {
            return true;
        }
#ifdef _WIN32
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
            error = "WSAStartup failed";
            return false;
        }
        winsockStarted_ = true;
#endif
        bindAddress_ = bindAddress;
        port_ = port;
        running_ = true;
        worker_ = std::thread([this]() { serve(); });
        return true;
    }

    void stop() {
        if (!running_) {
            return;
        }
        running_ = false;
        if (worker_.joinable()) {
            worker_.join();
        }
#ifdef _WIN32
        if (winsockStarted_) {
            WSACleanup();
            winsockStarted_ = false;
        }
#endif
    }

    void publish(const ProcessSnapshot& snapshot, const AppOptions& options, const UiState& ui, const AlertRuleService& rules, const IntegrationHub& hub, const HistoryTracker& history) {
        std::lock_guard<std::mutex> lock(mutex_);
        state_.snapshot = snapshot;
        state_.options = options;
        state_.ui = ui;
        state_.snapshotJson = SnapshotJson(SnapshotDtoFactory::make(snapshot, options, ui, &history));
        state_.events = IntegrationExporter::eventsNdjson(hub);
        state_.metrics = IntegrationExporter::prometheusText(snapshot, ui, rules, hub, &history);
        state_.rules = RulesJson(rules);
        state_.processHistory = HistoryJson(history.eventsFor(HistoryKind::Process));
        state_.serviceHistory = HistoryJson(history.eventsFor(HistoryKind::Service));
        state_.startupHistory = HistoryJson(history.eventsFor(HistoryKind::Startup));
        state_.driverHistory = HistoryJson(history.eventsFor(HistoryKind::Driver));
        const TraceBackendInfo trace = DetectTraceBackends();
        state_.health = "{ \"status\": \"ok\", \"app\": \"" + std::string(AppName) +
            "\", \"processBackend\": \"" + JsonEscape(trace.processBackend) +
            "\", \"serviceBackend\": \"" + JsonEscape(trace.serviceBackend) +
            "\", \"startupBackend\": \"" + JsonEscape(trace.startupBackend) +
            "\", \"driverBackend\": \"" + JsonEscape(trace.driverBackend) +
            "\", \"ebpfCompiled\": " + (trace.ebpfCompiled ? "true" : "false") + " }\n";
        state_.ready = true;
    }

private:
#ifdef _WIN32
    using Socket = SOCKET;
    static constexpr Socket InvalidSocket = INVALID_SOCKET;
#else
    using Socket = int;
    static constexpr Socket InvalidSocket = -1;
#endif

    void serve() {
        Socket server = createServerSocket();
        if (server == InvalidSocket) {
            running_ = false;
            return;
        }

        while (running_) {
            fd_set readSet;
            FD_ZERO(&readSet);
            FD_SET(server, &readSet);
            timeval timeout{ 0, 200000 };
            const int ready = select(static_cast<int>(server + 1), &readSet, nullptr, nullptr, &timeout);
            if (ready <= 0 || !FD_ISSET(server, &readSet)) {
                continue;
            }

            Socket client = accept(server, nullptr, nullptr);
            if (client == InvalidSocket) {
                continue;
            }
            handleClient(client);
            closeSocket(client);
        }
        closeSocket(server);
    }

    Socket createServerSocket() const {
        Socket server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (server == InvalidSocket) {
            return InvalidSocket;
        }

        int enabled = 1;
        setsockopt(server, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&enabled), sizeof(enabled));

        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(static_cast<unsigned short>(port_));
        if (inet_pton(AF_INET, bindAddress_.c_str(), &address.sin_addr) != 1) {
            closeSocket(server);
            return InvalidSocket;
        }

        if (bind(server, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 || listen(server, 8) != 0) {
            closeSocket(server);
            return InvalidSocket;
        }
        return server;
    }

    void handleClient(Socket client) {
        char buffer[1024]{};
        const int received = recv(client, buffer, static_cast<int>(sizeof(buffer) - 1), 0);
        if (received <= 0) {
            return;
        }

        std::istringstream request(std::string(buffer, static_cast<std::size_t>(received)));
        std::string method;
        std::string target;
        request >> method >> target;
        if (method != "GET") {
            sendResponse(client, 405, "text/plain; charset=utf-8", "method not allowed\n");
            return;
        }

        ApiState current;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            current = state_;
        }

        if (target == "/health") {
            const std::string body = current.health.empty()
                ? "{ \"status\": \"starting\", \"app\": \"" + std::string(AppName) + "\" }\n"
                : current.health;
            sendResponse(client, 200, "application/json; charset=utf-8", body);
            return;
        }

        if (!current.ready) {
            sendResponse(client, 503, "text/plain; charset=utf-8", "snapshot not ready\n");
            return;
        }
        if (target == "/snapshot") {
            sendResponse(client, 200, "application/json; charset=utf-8", current.snapshotJson);
        } else if (target == "/events") {
            sendResponse(client, 200, "application/x-ndjson; charset=utf-8", current.events);
        } else if (target == "/metrics") {
            sendResponse(client, 200, "text/plain; version=0.0.4; charset=utf-8", current.metrics);
        } else if (target == "/rules") {
            sendResponse(client, 200, "application/json; charset=utf-8", current.rules);
        } else if (target == "/history/processes") {
            sendResponse(client, 200, "application/json; charset=utf-8", current.processHistory);
        } else if (target == "/history/services") {
            sendResponse(client, 200, "application/json; charset=utf-8", current.serviceHistory);
        } else if (target == "/history/startup") {
            sendResponse(client, 200, "application/json; charset=utf-8", current.startupHistory);
        } else if (target == "/history/drivers") {
            sendResponse(client, 200, "application/json; charset=utf-8", current.driverHistory);
        } else {
            sendResponse(client, 404, "text/plain; charset=utf-8", "not found\n");
        }
    }

    static void sendResponse(Socket client, int status, const std::string& contentType, const std::string& body) {
        const std::string reason = status == 200 ? "OK" : (status == 404 ? "Not Found" : (status == 405 ? "Method Not Allowed" : "Service Unavailable"));
        std::ostringstream response;
        response << "HTTP/1.1 " << status << " " << reason << "\r\n"
                 << "Content-Type: " << contentType << "\r\n"
                 << "Content-Length: " << body.size() << "\r\n"
                 << "Connection: close\r\n"
                 << "Access-Control-Allow-Origin: http://127.0.0.1\r\n"
                 << "\r\n"
                 << body;
        const std::string text = response.str();
        send(client, text.c_str(), static_cast<int>(text.size()), 0);
    }

    static void closeSocket(Socket socket) {
#ifdef _WIN32
        closesocket(socket);
#else
        close(socket);
#endif
    }

    std::atomic<bool> running_{ false };
    std::thread worker_;
    std::mutex mutex_;
    ApiState state_;
    std::string bindAddress_ = "127.0.0.1";
    int port_ = 8765;
#ifdef _WIN32
    bool winsockStarted_ = false;
#endif
};

class ConsoleWindow {
public:
    static void enableVirtualTerminal() {
#ifdef _WIN32
        HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        if (output == INVALID_HANDLE_VALUE) {
            return;
        }

        DWORD mode = 0;
        if (GetConsoleMode(output, &mode)) {
            SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }

        HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
        if (input != INVALID_HANDLE_VALUE && GetConsoleMode(input, &mode)) {
            mode |= ENABLE_EXTENDED_FLAGS;
            mode &= ~ENABLE_QUICK_EDIT_MODE;
            mode &= ~ENABLE_INSERT_MODE;
            SetConsoleMode(input, mode);
        }
#endif
    }

#ifdef _WIN32
    static CONSOLE_SCREEN_BUFFER_INFO info() {
        CONSOLE_SCREEN_BUFFER_INFO value{};
        if (!GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &value)) {
            value.srWindow.Left = 0;
            value.srWindow.Top = 0;
            value.srWindow.Right = 119;
            value.srWindow.Bottom = 34;
        }
        return value;
    }
#endif

    static ConsoleSize size() {
#ifdef _WIN32
        const auto value = info();
        return {
            std::max(1, static_cast<int>(value.srWindow.Right - value.srWindow.Left + 1)),
            std::max(1, static_cast<int>(value.srWindow.Bottom - value.srWindow.Top + 1))
        };
#else
        winsize value{};
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &value) == 0 && value.ws_col > 0 && value.ws_row > 0) {
            return { static_cast<int>(value.ws_col), static_cast<int>(value.ws_row) };
        }
        return { 120, 35 };
#endif
    }

    static int width() {
        return size().width;
    }

    static int height() {
        return size().height;
    }
};

class InputController {
public:
    InputController() {
#ifndef _WIN32
        if (tcgetattr(STDIN_FILENO, &originalTermios_) == 0) {
            termios raw = originalTermios_;
            raw.c_lflag &= ~(ICANON | ECHO);
            raw.c_cc[VMIN] = 0;
            raw.c_cc[VTIME] = 0;
            tcsetattr(STDIN_FILENO, TCSANOW, &raw);
            configured_ = true;
        }
#endif
    }

    ~InputController() {
#ifndef _WIN32
        if (configured_) {
            tcsetattr(STDIN_FILENO, TCSANOW, &originalTermios_);
        }
#endif
    }

    Command readCommand() const {
        if (!hasKey()) {
            return Command::None;
        }

        int key = readKey();
#ifdef _WIN32
        if (key == 0 || key == 224) {
            key = readKey();
            const bool tabHeld = (GetAsyncKeyState(VK_TAB) & 0x8000) != 0;
            switch (key) {
            case 59: return Command::ToggleHelp;      // F1
            case 72: return tabHeld ? Command::PageUp : Command::MoveUp;
            case 80: return tabHeld ? Command::PageDown : Command::MoveDown;
            case 75: return Command::ScrollPathLeft;
            case 77: return Command::ScrollPathRight;
            case 73: return Command::PageUp;
            case 81: return Command::PageDown;
            case 71: return Command::JumpTop;
            case 79: return Command::JumpBottom;
            default: return Command::None;
            }
        }
#else
        if (key == 27) {
            if (!hasKey()) {
                return Command::Back;
            }
            const int next = readKey();
            if (next != '[' && next != 'O') {
                return Command::Back;
            }
            const int code = readKey();
            if (code >= '0' && code <= '9') {
                const int final = readKey();
                if (code == '1' && final == '~') return Command::JumpTop;
                if (code == '4' && final == '~') return Command::JumpBottom;
                if (code == '5' && final == '~') return Command::PageUp;
                if (code == '6' && final == '~') return Command::PageDown;
                return Command::None;
            }
            switch (code) {
            case 'A': return Command::MoveUp;
            case 'B': return Command::MoveDown;
            case 'C': return Command::ScrollPathRight;
            case 'D': return Command::ScrollPathLeft;
            case 'H': return Command::JumpTop;
            case 'F': return Command::JumpBottom;
            case 'P': return Command::ToggleHelp;
            default: return Command::None;
            }
        }
#endif

        switch (key) {
        case 'q':
        case 'Q': return Command::Quit;
        case '\t': return Command::FocusNextPane;
        case '\r': return Command::ActivateSelection;
        case 27: return Command::Back;
        case '?': return Command::ToggleHelp;
        case 'd':
        case 'D': return Command::Deselect;
        case ']': return Command::NextRightPaneMode;
        case '[': return Command::PrevRightPaneMode;
        case 'x':
        case 'X': return Command::HuntFocused;
        case 'g':
        case 'G': return Command::SubtreeFocused;
        case 's':
        case 'S': return Command::CycleSort;
        case 'v':
        case 'V': return Command::CycleView;
        case '/': return Command::PromptFilter;
        case 'c':
        case 'C': return Command::ClearContext;
        case 't':
        case 'T': return Command::PromptSubtree;
        case 'k':
        case 'K': return Command::RequestKill;
        case 'y':
        case 'Y': return Command::ConfirmYes;
        case 'n':
        case 'N': return Command::ConfirmNo;
        case 'h':
        case 'H': return Command::ToggleHunt;
        case '1': return Command::ShowProcessTab;
        case '2': return Command::ShowRegistryTab;
        case '3': return Command::ShowDriversTab;
        case '+':
        case '=': return Command::FasterRefresh;
        case '-':
        case '_': return Command::SlowerRefresh;
        case ' ': return Command::TogglePause;
        case 'e':
        case 'E': return Command::ExportSnapshot;
        default: return Command::None;
        }
    }

private:
    static bool hasKey() {
#ifdef _WIN32
        return _kbhit() != 0;
#else
        timeval timeout{ 0, 0 };
        fd_set set;
        FD_ZERO(&set);
        FD_SET(STDIN_FILENO, &set);
        return select(STDIN_FILENO + 1, &set, nullptr, nullptr, &timeout) > 0;
#endif
    }

    static int readKey() {
#ifdef _WIN32
        return _getch();
#else
        unsigned char c = 0;
        return read(STDIN_FILENO, &c, 1) == 1 ? c : 0;
#endif
    }

#ifndef _WIN32
    termios originalTermios_{};
    bool configured_ = false;
#endif
};

class Renderer {
public:
    void render(const ProcessSnapshot& snapshot, const AppOptions& options, UiState& ui) const {
        const Layout layout = makeLayout(ConsoleWindow::size(), options);
        if (ui.showHelp) {
            renderHelpScreen(layout.width, layout.height);
            std::cout.flush();
            return;
        }
        if (layout.tooSmall) {
            renderTooSmall(layout);
            std::cout.flush();
            return;
        }

        if (ui.activeTab != AppTab::Processes) {
            renderSystemTab(snapshot, options, ui, layout);
            std::cout.flush();
            return;
        }

        const auto byPid = indexByPid(snapshot.processes);
        auto rows = buildRows(snapshot.processes, options, ui);
        ensureBrowseOrderPinned(ui, rows, options);
        if (!layout.twoPane && ui.focusPane == FocusPane::GroupMembers) {
            ui.focusPane = FocusPane::ProcessList;
        }

        stabilizeSelection(ui, rows, layout.visibleRows);
        if (ui.selectionActive) {
            if (ui.rightPaneMode == RightPaneMode::Services || ui.rightPaneMode == RightPaneMode::Drivers || ui.rightPaneMode == RightPaneMode::Registry) {
                const auto entries = rightSystemEntriesForActions(snapshot, options, ui.rightPaneMode);
                clampRightList(ui, static_cast<int>(entries.size()), std::max(0, layout.height - 19));
            } else {
                const auto rightItems = rightPaneItemsForActions(snapshot.processes, options, ui);
                clampRightList(ui, static_cast<int>(rightItems.size()), std::max(0, layout.height - 22));
            }
        }

        const ProcessInfo* selected = findSelectedProcess(byPid, ui);

        std::cout << "\x1b[?25l\x1b[H";
        renderHeader(layout.width, options, ui);
        renderLeftPane(layout.leftWidth, layout.visibleRows, rows, byPid, ui);
        if (layout.twoPane) {
            renderDivider(layout.leftWidth, layout.height);
            renderRightPane(layout.rightCol, layout.rightWidth, layout.height, snapshot, options, selected, ui);
        }
        renderStatusBar(layout.height, layout.leftWidth, snapshot, rows, options, ui);
        std::cout << "\x1b[J";
        std::cout.flush();
    }

    std::vector<DisplayRow> rowsForActions(const std::vector<ProcessInfo>& processes, const AppOptions& options, const UiState& ui) const {
        return buildRows(processes, options, ui);
    }

    std::vector<ProcessInfo> groupMembersForActions(const std::vector<ProcessInfo>& processes, const AppOptions& options, const UiState& ui) const {
        return buildSelectedGroupMembers(processes, options, ui.selectedPid);
    }

    std::vector<ProcessInfo> rightPaneItemsForActions(const std::vector<ProcessInfo>& processes, const AppOptions& options, const UiState& ui) const {
        if (!ui.selectionActive) {
            return {};
        }
        if (ui.rightPaneMode == RightPaneMode::Children) {
            return buildChildrenOfSelected(processes, options, ui.selectedPid);
        }
        if (ui.rightPaneMode == RightPaneMode::Members) {
            return buildSelectedGroupMembers(processes, options, ui.selectedPid);
        }
        return {};
    }

    std::vector<SystemEntry> systemEntriesForActions(const ProcessSnapshot& snapshot, const AppOptions& options, AppTab tab) const {
        if (tab == AppTab::Registry) {
            return FilterSystemEntries(snapshot.registryKeys, options);
        }
        if (tab == AppTab::Drivers) {
            return FilterSystemEntries(snapshot.drivers, options);
        }
        return {};
    }

    std::vector<SystemEntry> rightSystemEntriesForActions(const ProcessSnapshot& snapshot, const AppOptions& options, RightPaneMode mode) const {
        if (mode == RightPaneMode::Services) {
            return FilterSystemEntries(snapshot.services, options);
        }
        if (mode == RightPaneMode::Drivers) {
            return FilterSystemEntries(snapshot.drivers, options);
        }
        if (mode == RightPaneMode::Registry) {
            return FilterSystemEntries(snapshot.registryKeys, options);
        }
        return {};
    }

    int maxRows(const AppOptions& options) const {
        return makeLayout(ConsoleWindow::size(), options).visibleRows;
    }

private:
    struct Layout {
        int width = 120;
        int height = 35;
        int leftWidth = 120;
        int rightWidth = 0;
        int rightCol = 0;
        int visibleRows = 4;
        bool twoPane = false;
        bool tooSmall = false;
    };

    static Layout makeLayout(ConsoleSize size, const AppOptions& options) {
        Layout layout;
        layout.width = std::max(1, size.width);
        layout.height = std::max(1, size.height);
        layout.tooSmall = layout.width < 52 || layout.height < 12;
        layout.twoPane = !layout.tooSmall && layout.width >= 112 && layout.height >= 18;
        layout.rightWidth = layout.twoPane ? std::max(34, std::min(58, layout.width / 3)) : 0;
        layout.leftWidth = layout.twoPane ? std::max(1, layout.width - layout.rightWidth - 3) : layout.width;
        layout.rightCol = layout.twoPane ? layout.leftWidth + 4 : 0;
        const int automaticRows = std::max(1, layout.height - 7);
        layout.visibleRows = options.rowLimit > 0 ? std::max(1, std::min(options.rowLimit, automaticRows)) : automaticRows;
        return layout;
    }

    static std::unordered_map<DWORD, ProcessInfo> indexByPid(const std::vector<ProcessInfo>& processes) {
        std::unordered_map<DWORD, ProcessInfo> byPid;
        for (const auto& process : processes) {
            byPid[process.pid] = process;
        }
        return byPid;
    }

    static std::unordered_map<DWORD, std::vector<DWORD>> buildChildren(const std::vector<ProcessInfo>& processes) {
        std::unordered_map<DWORD, std::vector<DWORD>> children;
        for (const auto& process : processes) {
            children[process.parentPid].push_back(process.pid);
        }
        return children;
    }

    static bool hasMatchingDescendant(
        DWORD pid,
        const std::unordered_map<DWORD, ProcessInfo>& byPid,
        const std::unordered_map<DWORD, std::vector<DWORD>>& children,
        const AppOptions& options,
        std::set<DWORD>& visited
    ) {
        if (visited.count(pid) != 0) {
            return false;
        }
        visited.insert(pid);

        const auto childList = children.find(pid);
        if (childList == children.end()) {
            return false;
        }

        for (DWORD childPid : childList->second) {
            if (childPid == pid) {
                continue;
            }
            const auto child = byPid.find(childPid);
            if (child != byPid.end() && (MatchesFilter(child->second, options) || hasMatchingDescendant(childPid, byPid, children, options, visited))) {
                return true;
            }
        }
        return false;
    }

    static void appendTreeRows(
        DWORD pid,
        int depth,
        std::set<DWORD>& visited,
        const std::unordered_map<DWORD, ProcessInfo>& byPid,
        std::unordered_map<DWORD, std::vector<DWORD>>& children,
        const AppOptions& options,
        std::vector<DisplayRow>& rows
    ) {
        if (visited.count(pid) != 0) {
            return;
        }

        const auto process = byPid.find(pid);
        if (process == byPid.end()) {
            return;
        }

        visited.insert(pid);
        std::set<DWORD> descendantVisited;
        const bool processMatches = MatchesFilter(process->second, options);
        const bool descendantMatches = hasMatchingDescendant(pid, byPid, children, options, descendantVisited);
        if (processMatches || descendantMatches || options.subtreePid != 0) {
            rows.push_back({ pid, std::string(static_cast<std::size_t>(depth * 2), ' ') + process->second.name, false, 0 });
        }

        auto childList = children.find(pid);
        if (childList == children.end()) {
            return;
        }

        std::sort(childList->second.begin(), childList->second.end(), [&](DWORD leftPid, DWORD rightPid) {
            return ComesBefore(byPid.at(leftPid), byPid.at(rightPid), options.sortMode);
        });

        for (DWORD childPid : childList->second) {
            if (childPid != pid) {
                appendTreeRows(childPid, depth + 1, visited, byPid, children, options, rows);
            }
        }
    }

    static std::vector<DisplayRow> buildRows(const std::vector<ProcessInfo>& processes, const AppOptions& options, const UiState& ui) {
        std::vector<DisplayRow> rows;
        if (options.viewMode == ViewMode::Tree) {
            auto byPid = indexByPid(processes);
            auto children = buildChildren(processes);
            std::set<DWORD> visited;

            if (options.subtreePid != 0 && byPid.find(options.subtreePid) != byPid.end()) {
                appendTreeRows(options.subtreePid, 0, visited, byPid, children, options, rows);
            } else {
                std::vector<DWORD> roots;
                for (const auto& process : processes) {
                    if (byPid.find(process.parentPid) == byPid.end() || process.pid == process.parentPid) {
                        roots.push_back(process.pid);
                    }
                }
                std::sort(roots.begin(), roots.end(), [&](DWORD leftPid, DWORD rightPid) {
                    return ComesBefore(byPid.at(leftPid), byPid.at(rightPid), options.sortMode);
                });
                for (DWORD root : roots) {
                    appendTreeRows(root, 0, visited, byPid, children, options, rows);
                }
                for (const auto& process : processes) {
                    appendTreeRows(process.pid, 0, visited, byPid, children, options, rows);
                }
            }
        } else {
            for (const auto& process : processes) {
                if (MatchesFilter(process, options)) {
                    rows.push_back({ process.pid, process.name, false, 0 });
                }
            }
        }

        for (const auto& item : ui.fadingGone) {
            const auto age = ui.fadingAge.find(item.first);
            rows.push_back({ item.first, item.second.name + " (gone)", true, age == ui.fadingAge.end() ? 0 : age->second });
        }
        applyHeldOrder(rows, ui);
        return rows;
    }

    static void applyHeldOrder(std::vector<DisplayRow>& rows, const UiState& ui) {
        if (!ui.sortOrderPinned || ui.heldRowOrder.empty() || rows.size() < 2) {
            return;
        }

        std::unordered_map<DWORD, std::size_t> rank;
        for (std::size_t i = 0; i < ui.heldRowOrder.size(); ++i) {
            rank[ui.heldRowOrder[i]] = i;
        }

        std::stable_sort(rows.begin(), rows.end(), [&](const DisplayRow& left, const DisplayRow& right) {
            const auto leftRank = rank.find(left.pid);
            const auto rightRank = rank.find(right.pid);
            const bool leftHeld = leftRank != rank.end();
            const bool rightHeld = rightRank != rank.end();
            if (leftHeld && rightHeld) {
                return leftRank->second < rightRank->second;
            }
            if (leftHeld != rightHeld) {
                return leftHeld;
            }
            return false;
        });
    }

    static bool isVolatileBrowseSort(const AppOptions& options) {
        return options.viewMode != ViewMode::Tree && (options.sortMode == SortMode::Cpu || options.sortMode == SortMode::Memory);
    }

    static void ensureBrowseOrderPinned(UiState& ui, const std::vector<DisplayRow>& rows, const AppOptions& options) {
        if (!isVolatileBrowseSort(options) || rows.empty()) {
            return;
        }
        if (ui.sortOrderPinned && !ui.heldRowOrder.empty()) {
            return;
        }
        ui.heldRowOrder.clear();
        ui.heldRowOrder.reserve(rows.size());
        for (const auto& row : rows) {
            ui.heldRowOrder.push_back(row.pid);
        }
        ui.sortOrderPinned = true;
    }

    static const ProcessInfo* findByPid(const std::unordered_map<DWORD, ProcessInfo>& byPid, DWORD pid) {
        const auto found = byPid.find(pid);
        return found == byPid.end() ? nullptr : &found->second;
    }

    static const ProcessInfo* findSelectedProcess(const std::unordered_map<DWORD, ProcessInfo>& byPid, const UiState& ui) {
        if (!ui.selectionActive) {
            return nullptr;
        }
        const auto live = byPid.find(ui.selectedPid);
        if (live != byPid.end()) {
            return &live->second;
        }
        const auto gone = ui.fadingGone.find(ui.selectedPid);
        return gone == ui.fadingGone.end() ? nullptr : &gone->second;
    }

    static void stabilizeSelection(UiState& ui, const std::vector<DisplayRow>& rows, int visibleRows) {
        if (rows.empty()) {
            ui.selectedIndex = 0;
            ui.selectedPid = 0;
            ui.selectionActive = false;
            ui.scroll = 0;
            return;
        }

        if (!ui.selectionActive) {
            ui.selectedIndex = std::max(0, std::min(ui.selectedIndex, static_cast<int>(rows.size()) - 1));
            ui.scroll = std::max(0, std::min(ui.scroll, std::max(0, static_cast<int>(rows.size()) - visibleRows)));
            return;
        }

        if (ui.selectedPid != 0) {
            for (int i = 0; i < static_cast<int>(rows.size()); ++i) {
                if (rows[static_cast<std::size_t>(i)].pid == ui.selectedPid) {
                    ui.selectedIndex = i;
                    break;
                }
            }
        }

        ui.selectedIndex = std::max(0, std::min(ui.selectedIndex, static_cast<int>(rows.size()) - 1));
        ui.selectedPid = rows[static_cast<std::size_t>(ui.selectedIndex)].pid;
        if (ui.selectedIndex < ui.scroll) {
            ui.scroll = ui.selectedIndex;
        }
        if (ui.selectedIndex >= ui.scroll + visibleRows) {
            ui.scroll = ui.selectedIndex - visibleRows + 1;
        }
        ui.scroll = std::max(0, std::min(ui.scroll, std::max(0, static_cast<int>(rows.size()) - visibleRows)));
    }

    static void clampRightList(UiState& ui, int itemCount, int visibleRows) {
        if (itemCount <= 0) {
            ui.rightSelectedIndex = 0;
            ui.rightScroll = 0;
            return;
        }

        ui.rightSelectedIndex = std::max(0, std::min(ui.rightSelectedIndex, itemCount - 1));
        ui.rightScroll = std::max(0, std::min(ui.rightScroll, std::max(0, itemCount - visibleRows)));
        if (ui.rightSelectedIndex < ui.rightScroll) {
            ui.rightScroll = ui.rightSelectedIndex;
        }
        if (visibleRows > 0 && ui.rightSelectedIndex >= ui.rightScroll + visibleRows) {
            ui.rightScroll = ui.rightSelectedIndex - visibleRows + 1;
        }
    }

    static std::string fitLine(const std::string& text, int width) {
        if (width <= 0) {
            return {};
        }
        if (static_cast<int>(text.size()) >= width) {
            return text.substr(0, static_cast<std::size_t>(width));
        }
        return text + std::string(static_cast<std::size_t>(width - text.size()), ' ');
    }

    static std::string field(const std::string& label, const std::string& value, int width) {
        return fitLine(label + ": " + value, width);
    }

    static void printAt(int row, int col, const std::string& text) {
        if (row <= 0 || col <= 0) {
            return;
        }
        std::cout << "\x1b[" << row << ";" << col << "H" << text;
    }

    static void printBoxLine(int row, int col, int width, const std::string& text, const char* color = Ansi::Reset) {
        if (width <= 0) {
            return;
        }
        printAt(row, col, std::string(color) + fitLine(text, width) + Ansi::Reset);
    }

    static void renderTooSmall(const Layout& layout) {
        std::cout << "\x1b[?25l\x1b[H";
        for (int row = 1; row <= layout.height; ++row) {
            printBoxLine(row, 1, layout.width, "");
        }
        printBoxLine(1, 1, layout.width, AppName, Ansi::Cyan);
        printBoxLine(3, 1, layout.width, "Window is too small", Ansi::Orange);
        printBoxLine(4, 1, layout.width, "Resize to at least 52x12", Ansi::Dim);
        printBoxLine(6, 1, layout.width, "q quit | F1 help", Ansi::Dim);
        std::cout << "\x1b[J";
    }

    static const char* notificationColor(NotificationKind kind) {
        switch (kind) {
        case NotificationKind::Success: return Ansi::Green;
        case NotificationKind::Warning: return Ansi::Orange;
        case NotificationKind::Error: return Ansi::Red;
        case NotificationKind::Info: return Ansi::Cyan;
        }
        return Ansi::Cyan;
    }

    static void renderHeader(int width, const AppOptions& options, const UiState& ui) {
        std::ostringstream title;
        title << AppName << " | view " << ViewName(options.viewMode)
              << " | sort " << SortName(options.sortMode)
              << " | refresh " << options.refreshMs << "ms"
              << " | tab " << TabName(ui.activeTab)
              << " | filter " << (options.filter.empty() ? "<none>" : options.filter)
              << " | " << (ui.paused ? "paused" : "live");
        printBoxLine(1, 1, width, title.str(), Ansi::Cyan);
        const std::string hints = width >= 112
            ? "1 proc | 2 " + StartupAreaName() + " | 3 drivers | / filter | F1 help | PgUp/PgDn | Tab pane | q quit"
            : "1 proc | 2 " + StartupAreaName() + " | 3 drivers | / filter | F1 help | PgUp/PgDn | q quit";
        printBoxLine(2, 1, width, hints, Ansi::Dim);
    }

    static void renderLeftPane(
        int leftWidth,
        int visibleRows,
        const std::vector<DisplayRow>& rows,
        const std::unordered_map<DWORD, ProcessInfo>& byPid,
        const UiState& ui
    ) {
        std::ostringstream header;
        header << std::left
               << std::setw(7) << "PID"
               << std::setw(7) << "PPID"
               << std::setw(7) << "CPU"
               << std::setw(9) << "MEM"
               << std::setw(6) << "THR"
               << std::setw(24) << "NAME/TREE"
               << "PATH";
        printBoxLine(4, 1, leftWidth, header.str());
        printBoxLine(5, 1, leftWidth, std::string(static_cast<std::size_t>(leftWidth), '-'), Ansi::Dim);

        if (rows.empty()) {
            printBoxLine(7, 3, leftWidth - 4, "No rows to show. Clear filters or switch view.", Ansi::Orange);
            for (int i = 0; i < visibleRows; ++i) {
                if (6 + i != 7) {
                    printBoxLine(6 + i, 1, leftWidth, "");
                }
            }
            return;
        }

        for (int i = 0; i < visibleRows; ++i) {
            const int rowIndex = ui.scroll + i;
            const int screenRow = 6 + i;
            if (rowIndex >= static_cast<int>(rows.size())) {
                printBoxLine(screenRow, 1, leftWidth, "");
                continue;
            }

            const auto& row = rows[static_cast<std::size_t>(rowIndex)];
            const ProcessInfo* process = findByPid(byPid, row.pid);
            if (!process) {
                const auto gone = ui.fadingGone.find(row.pid);
                process = gone == ui.fadingGone.end() ? nullptr : &gone->second;
            }
            if (!process) {
                printBoxLine(screenRow, 1, leftWidth, "");
                continue;
            }

            const bool isCursor = rowIndex == ui.selectedIndex && ui.focusPane == FocusPane::ProcessList;
            const bool isSelected = ui.selectionActive && row.pid == ui.selectedPid;
            const bool isHunted = ui.hunt.active && row.pid == ui.hunt.pid;
            const bool isKillRequested = ui.killRequested.count(row.pid) != 0;

            const char* color = Ansi::Reset;
            if (row.gone) {
                color = row.goneAge < 5 ? Ansi::Red : Ansi::Grey;
            } else if (isKillRequested) {
                color = Ansi::RedBg;
            } else if (isCursor && isSelected) {
                color = Ansi::OrangeBg;
            } else if (isCursor) {
                color = Ansi::FocusBg;
            } else if (isSelected) {
                color = Ansi::Orange;
            } else if (isHunted) {
                color = ui.hunt.alert.empty() ? Ansi::Green : Ansi::Red;
            }

            const int pathWidth = std::max(8, leftWidth - 60);
            const std::string rawPath = process->path.display();
            const bool hasMoreLeft = ui.pathScroll > 0;
            const bool hasMoreRight = rawPath.size() > static_cast<std::size_t>(ui.pathScroll + pathWidth);
            std::string path = SliceTo(rawPath, static_cast<std::size_t>(ui.pathScroll), static_cast<std::size_t>(pathWidth));
            if (isCursor && (hasMoreLeft || hasMoreRight)) {
                if (!path.empty() && hasMoreLeft) {
                    path[0] = '<';
                }
                if (!path.empty() && hasMoreRight) {
                    path[path.size() - 1] = '>';
                }
            }

            std::ostringstream line;
            line << std::left
                 << std::setw(7) << process->pid
                 << std::setw(7) << process->parentPid
                 << std::setw(7) << std::fixed << std::setprecision(1) << process->cpu
                 << std::setw(9) << MemoryMb(process->workingSet)
                 << std::setw(6) << process->threads
                 << std::setw(24) << TrimTo(row.label, 23);

            if (ui.pathScroll > 0 && isCursor && leftWidth > 64) {
                printBoxLine(screenRow, 1, leftWidth, std::string(color) + fitLine(line.str(), 60) + Ansi::LightGreenBg + path + Ansi::Reset);
            } else {
                printBoxLine(screenRow, 1, leftWidth, line.str() + path, color);
            }
        }
    }

    static void renderSystemTab(const ProcessSnapshot& snapshot, const AppOptions& options, UiState& ui, const Layout& layout) {
        const std::vector<SystemEntry> entries = ui.activeTab == AppTab::Registry
            ? FilterSystemEntries(snapshot.registryKeys, options)
            : FilterSystemEntries(snapshot.drivers, options);
        ui.focusPane = FocusPane::ProcessList;
        ui.selectedIndex = std::max(0, std::min(ui.selectedIndex, std::max(0, static_cast<int>(entries.size()) - 1)));
        ui.scroll = std::max(0, std::min(ui.scroll, std::max(0, static_cast<int>(entries.size()) - layout.visibleRows)));
        if (ui.selectedIndex < ui.scroll) {
            ui.scroll = ui.selectedIndex;
        }
        if (ui.selectedIndex >= ui.scroll + layout.visibleRows) {
            ui.scroll = ui.selectedIndex - layout.visibleRows + 1;
        }

        std::cout << "\x1b[?25l\x1b[H";
        renderHeader(layout.width, options, ui);
        const std::string title = ui.activeTab == AppTab::Registry ? StartupAreaTitle() : "KERNEL DRIVERS";
        printBoxLine(4, 1, layout.width, title, Ansi::Cyan);
        printBoxLine(5, 1, layout.width, ui.activeTab == AppTab::Registry ? StartupAreaColumnTitle() : "DRIVER / PATH", Ansi::Dim);

        if (entries.empty()) {
            printBoxLine(7, 3, layout.width - 4, options.filter.empty() ? "No entries visible or access denied." : "No entries match the filter.", Ansi::Orange);
        }

        for (int i = 0; i < layout.visibleRows; ++i) {
            const int index = ui.scroll + i;
            const int row = 6 + i;
            if (index >= static_cast<int>(entries.size())) {
                printBoxLine(row, 1, layout.width, "");
                continue;
            }
            const auto& entry = entries[static_cast<std::size_t>(index)];
            const bool cursor = index == ui.selectedIndex;
            const bool selected = ui.systemSelectionActive &&
                ui.selectedSystemTab == ui.activeTab &&
                ui.selectedSystemKey == entry.type + ":" + entry.name;
            const std::string line = entry.name + "  " + entry.detail;
            printBoxLine(row, 1, layout.width, line, cursor ? Ansi::FocusBg : (selected ? Ansi::Orange : Ansi::Reset));
        }

        std::ostringstream status;
        status << "tab " << TabName(ui.activeTab)
               << " | rows " << (entries.empty() ? 0 : ui.selectedIndex + 1) << "/" << entries.size()
               << " | 1 processes | 2 " << StartupAreaName() << " | 3 drivers | / filter | " << (ui.message.text.empty() ? "ready" : ui.message.text);
        printBoxLine(layout.height, 1, layout.width, status.str(), ui.message.ttlFrames > 0 ? notificationColor(ui.message.kind) : Ansi::Dim);
        std::cout << "\x1b[J";
    }

    static std::vector<ProcessGroup> buildGroups(const std::vector<ProcessInfo>& processes, const AppOptions& options) {
        std::map<std::string, ProcessGroup> groups;
        for (const auto& process : processes) {
            if (!MatchesFilter(process, options)) {
                continue;
            }

            const std::string key = process.name.empty() ? "<unknown>" : ToLower(process.name);
            auto& group = groups[key];
            group.name = process.name.empty() ? "<unknown>" : process.name;
            group.count += 1;
            group.cpu += process.cpu;
            group.workingSet += process.workingSet;
            group.threads += process.threads;
            group.pids.push_back(process.pid);
        }

        std::vector<ProcessGroup> result;
        for (auto& item : groups) {
            result.push_back(std::move(item.second));
        }

        std::sort(result.begin(), result.end(), [&](const ProcessGroup& left, const ProcessGroup& right) {
            switch (options.sortMode) {
            case SortMode::Cpu:
                return left.cpu == right.cpu ? ToLower(left.name) < ToLower(right.name) : left.cpu > right.cpu;
            case SortMode::Memory:
                return left.workingSet == right.workingSet ? ToLower(left.name) < ToLower(right.name) : left.workingSet > right.workingSet;
            case SortMode::Pid:
                return left.pids.front() < right.pids.front();
            case SortMode::Name:
                return ToLower(left.name) < ToLower(right.name);
            }
            return ToLower(left.name) < ToLower(right.name);
        });
        return result;
    }

    static std::vector<ProcessInfo> buildSelectedGroupMembers(const std::vector<ProcessInfo>& processes, const AppOptions& options, DWORD selectedPid) {
        const ProcessInfo* selected = nullptr;
        for (const auto& process : processes) {
            if (process.pid == selectedPid) {
                selected = &process;
                break;
            }
        }

        std::vector<ProcessInfo> members;
        if (!selected) {
            return members;
        }

        const std::string selectedName = ToLower(selected->name);
        for (const auto& process : processes) {
            if (ToLower(process.name) == selectedName && MatchesFilter(process, options)) {
                members.push_back(process);
            }
        }

        std::sort(members.begin(), members.end(), [&](const ProcessInfo& left, const ProcessInfo& right) {
            return ComesBefore(left, right, options.sortMode);
        });
        return members;
    }

    static std::vector<ProcessInfo> buildChildrenOfSelected(const std::vector<ProcessInfo>& processes, const AppOptions& options, DWORD selectedPid) {
        std::vector<ProcessInfo> children;
        for (const auto& process : processes) {
            if (process.parentPid == selectedPid && process.pid != selectedPid && MatchesFilter(process, options)) {
                children.push_back(process);
            }
        }

        std::sort(children.begin(), children.end(), [&](const ProcessInfo& left, const ProcessInfo& right) {
            return ComesBefore(left, right, options.sortMode);
        });
        return children;
    }

    static void renderRightPane(
        int col,
        int width,
        int height,
        const ProcessSnapshot& snapshot,
        const AppOptions& options,
        const ProcessInfo* selected,
        const UiState& ui
    ) {
        const auto& processes = snapshot.processes;
        printBoxLine(4, col, width, "SELECTED PROCESS", Ansi::Cyan);
        if (selected) {
            printBoxLine(5, col, width, field("pid", std::to_string(selected->pid), width));
            printBoxLine(6, col, width, field("name", selected->name, width));
            printBoxLine(7, col, width, field("sid", selected->sid.ok() ? selected->sid.value : selected->sid.status, width));
            printBoxLine(8, col, width, field("svc", selected->service.empty() ? "<none>" : selected->service, width));
            printBoxLine(9, col, width, field("path", selected->path.ok() ? selected->path.value : selected->path.status, width));
            printBoxLine(10, col, width, field("cpu/mem", std::to_string(static_cast<int>(selected->cpu)) + "% / " + MemoryMb(selected->workingSet) + " MB", width));
        } else {
            printBoxLine(5, col, width, "<nothing selected>", Ansi::Dim);
            for (int row = 6; row <= 10; ++row) {
                printBoxLine(row, col, width, "");
            }
        }

        printBoxLine(12, col, width, "RIGHT PANE [" + RightPaneModeName(ui.rightPaneMode) + "]  [ ] switch", Ansi::Cyan);

        if (ui.rightPaneMode == RightPaneMode::Services || ui.rightPaneMode == RightPaneMode::Drivers || ui.rightPaneMode == RightPaneMode::Registry) {
            const std::vector<SystemEntry> entries = ui.rightPaneMode == RightPaneMode::Services
                ? FilterSystemEntries(snapshot.services, options)
                : (ui.rightPaneMode == RightPaneMode::Drivers ? FilterSystemEntries(snapshot.drivers, options) : FilterSystemEntries(snapshot.registryKeys, options));
            renderSystemEntries(col, width, height, entries, ui);
            return;
        }

        std::vector<ProcessInfo> items;
        ProcessGroup selectedGroup;
        if (selected && ui.selectionActive && ui.rightPaneMode == RightPaneMode::Members) {
            items = buildSelectedGroupMembers(processes, options, selected->pid);
            selectedGroup.name = selected->name;
            for (const auto& process : items) {
                selectedGroup.count += 1;
                selectedGroup.cpu += process.cpu;
                selectedGroup.workingSet += process.workingSet;
                selectedGroup.threads += process.threads;
                selectedGroup.pids.push_back(process.pid);
            }
        } else if (selected && ui.selectionActive && ui.rightPaneMode == RightPaneMode::Children) {
            items = buildChildrenOfSelected(processes, options, selected->pid);
        }

        if (ui.rightPaneMode == RightPaneMode::Details) {
            if (selected && ui.selectionActive) {
                const int childCount = static_cast<int>(buildChildrenOfSelected(processes, options, selected->pid).size());
                printBoxLine(13, col, width, "pid      " + std::to_string(selected->pid), Ansi::Orange);
                printBoxLine(14, col, width, "ppid     " + std::to_string(selected->parentPid));
                printBoxLine(15, col, width, "threads  " + std::to_string(selected->threads));
                printBoxLine(16, col, width, "children " + std::to_string(childCount));
                printBoxLine(17, col, width, "memory   " + MemoryMb(selected->workingSet) + " MB");
                printBoxLine(18, col, width, "cpu      " + std::to_string(static_cast<int>(selected->cpu)) + "%");
                printBoxLine(19, col, width, "service  " + (selected->service.empty() ? "<none>" : selected->service));
                printBoxLine(20, col, width, "signer   " + selected->signer);
                printBoxLine(21, col, width, "hash     " + selected->hash);
                printBoxLine(22, col, width, "cmd      " + selected->commandLine);
                printBoxLine(23, col, width, "path     " + selected->path.display());
                int clearFrom = 24;
                if (ui.hunt.active && ui.hunt.pid == selected->pid) {
                    std::ostringstream huntLine;
                    huntLine << "hunt     cpu " << std::fixed << std::setprecision(1) << ui.hunt.lastCpu
                             << "% peak " << ui.hunt.peakCpu
                             << "% mem " << MemoryMb(ui.hunt.lastWorkingSet)
                             << "/" << MemoryMb(ui.hunt.peakWorkingSet) << " MB";
                    printBoxLine(24, col, width, huntLine.str(), ui.hunt.alert.empty() ? Ansi::Green : Ansi::Red);
                    printBoxLine(25, col, width, "alert    " + (ui.hunt.alert.empty() ? std::string("none") : ui.hunt.alert), ui.hunt.alert.empty() ? Ansi::Dim : Ansi::Red);
                    clearFrom = 26;
                }
                for (int row = clearFrom; row < height - 5; ++row) {
                    printBoxLine(row, col, width, "");
                }
            } else {
                printBoxLine(13, col, width, "No process selected", Ansi::Orange);
                printBoxLine(14, col, width, "Enter selects a row");
                printBoxLine(15, col, width, "d or Esc clears selection");
                for (int row = 16; row < height - 5; ++row) {
                    printBoxLine(row, col, width, "");
                }
            }
        } else if (selected && ui.rightPaneMode == RightPaneMode::Members && !items.empty()) {
            std::ostringstream summary;
            summary << selectedGroup.count << "x " << selectedGroup.name
                    << " | cpu " << std::fixed << std::setprecision(1) << selectedGroup.cpu
                    << " | mem " << MemoryMb(selectedGroup.workingSet) << " MB";
            printBoxLine(14, col, width, summary.str(), Ansi::Orange);
        } else if (selected && ui.rightPaneMode == RightPaneMode::Children && !items.empty()) {
            printBoxLine(14, col, width, std::to_string(items.size()) + " child process(es)", Ansi::Orange);
        } else if (ui.rightPaneMode != RightPaneMode::Details) {
            printBoxLine(14, col, width, selected ? "No visible " + RightPaneModeName(ui.rightPaneMode) : "No process selected", Ansi::Orange);
            printBoxLine(15, col, width, selected ? "Filter may be hiding items" : "Select a process first", Ansi::Dim);
            printBoxLine(16, col, width, selected ? "Try another mode with [ or ]" : "Enter selects the focused row", Ansi::Dim);
        }

        if (ui.rightPaneMode != RightPaneMode::Details) {
            printBoxLine(13, col, width, "pid    cpu  memMB    service/name");
            const int maxMembers = std::max(0, height - 22);
            for (int i = 0; i < maxMembers; ++i) {
                const int rowNo = 16 + i;
                const int index = ui.rightScroll + i;
                if (index >= static_cast<int>(items.size())) {
                    if (rowNo > 16 || !items.empty()) {
                        printBoxLine(rowNo, col, width, "");
                    }
                    continue;
                }

                const auto& item = items[static_cast<std::size_t>(index)];
                std::ostringstream row;
                row << std::left
                    << std::setw(7) << item.pid
                    << std::setw(5) << static_cast<int>(item.cpu)
                    << std::setw(9) << MemoryMb(item.workingSet)
                    << (item.service.empty() ? item.name : item.service);

                const bool isRightCursor = ui.focusPane == FocusPane::GroupMembers && index == ui.rightSelectedIndex;
                const bool isSelectedMember = selected && item.pid == selected->pid;
                const bool isHuntedMember = ui.hunt.active && item.pid == ui.hunt.pid;
                printBoxLine(rowNo, col, width, row.str(), isRightCursor ? (isSelectedMember ? Ansi::OrangeBg : Ansi::FocusBg) : (isSelectedMember ? Ansi::Orange : (isHuntedMember ? Ansi::Green : Ansi::Reset)));
            }
        }

        printBoxLine(height - 4, col, width, "MODE HINTS", Ansi::Cyan);
        printBoxLine(height - 3, col, width, modeHints(options, ui), Ansi::Dim);
        if (ui.hunt.active) {
            const char* huntColor = ui.hunt.alert.empty() ? Ansi::Green : Ansi::Red;
            const std::string state = ui.hunt.alert.empty() ? ui.hunt.status : ui.hunt.alert;
            printBoxLine(height - 2, col, width, "hunt " + std::to_string(ui.hunt.pid) + " " + ui.hunt.name + ": " + state, huntColor);
        } else {
            printBoxLine(height - 2, col, width, "hunt: inactive", Ansi::Dim);
        }
        printBoxLine(height - 1, col, width, focusHint(ui), Ansi::Dim);
    }

    static void renderSystemEntries(int col, int width, int height, const std::vector<SystemEntry>& entries, const UiState& ui) {
        const RightPaneMode mode = ui.rightPaneMode;
        std::string heading;
        if (mode == RightPaneMode::Services) {
            heading = "service        pid      state";
        } else if (mode == RightPaneMode::Drivers) {
            heading = "kernel driver  path";
        } else {
            heading = StartupAreaColumnTitle();
        }

        printBoxLine(13, col, width, heading, Ansi::Dim);
        const int maxRows = std::max(0, height - 19);
        for (int i = 0; i < maxRows; ++i) {
            const int row = 15 + i;
            const int index = ui.rightScroll + i;
            if (index >= static_cast<int>(entries.size())) {
                printBoxLine(row, col, width, "");
                continue;
            }
            const auto& entry = entries[static_cast<std::size_t>(index)];
            std::ostringstream line;
            if (mode == RightPaneMode::Services) {
                line << std::left << std::setw(15) << TrimTo(entry.name, 14)
                     << std::setw(9) << entry.pid
                     << entry.detail;
            } else if (mode == RightPaneMode::Drivers) {
                line << std::left << std::setw(18) << TrimTo(entry.name, 17)
                     << std::setw(12) << TrimTo(entry.signer, 11)
                     << entry.detail;
            } else {
                line << entry.name << " [" << entry.signer << "] => " << entry.detail;
            }
            const bool cursor = ui.focusPane == FocusPane::GroupMembers && index == ui.rightSelectedIndex;
            printBoxLine(row, col, width, line.str(), cursor ? Ansi::FocusBg : (mode == RightPaneMode::Drivers ? Ansi::Orange : Ansi::Reset));
        }

        printBoxLine(height - 4, col, width, "TRACE SUMMARY", Ansi::Cyan);
        printBoxLine(height - 3, col, width, std::to_string(entries.size()) + " " + RightPaneModeName(mode) + " entries", Ansi::Dim);
        printBoxLine(height - 2, col, width, entries.empty() ? "no filtered entries" : "Enter follows PID when available", Ansi::Dim);
        printBoxLine(height - 1, col, width, focusHint(ui), Ansi::Dim);
    }

    static std::string focusHint(const UiState& ui) {
        if (ui.focusPane == FocusPane::GroupMembers) {
            if (ui.rightPaneMode == RightPaneMode::Details) {
                return "details active: [] modes, Esc back";
            }
            return "right active: Enter pick | x hunt | g subtree | Esc back";
        }
        return "left active: Enter select | Tab right | Esc deselect";
    }

    static std::string modeHints(const AppOptions& options, const UiState& ui) {
        if (ui.focusPane == FocusPane::GroupMembers) {
            if (ui.rightPaneMode == RightPaneMode::Details) {
                return "details: [] pane mode | Esc back";
            }
            return "right: Enter pick | x hunt | g subtree | PgUp/PgDn";
        }
        switch (options.viewMode) {
        case ViewMode::Tree:
            return "left tree: Enter select | Tab right | / filter";
        case ViewMode::Kernel:
            return "left kernel: Enter select | Esc deselect";
        case ViewMode::Table:
            return "left table: Enter select | Tab members | s sort";
        }
        return {};
    }

    static void renderDivider(int leftWidth, int height) {
        for (int row = 3; row <= height; ++row) {
            printBoxLine(row, leftWidth + 2, 1, "|", Ansi::Dim);
        }
    }

    static void renderStatusBar(
        int height,
        int leftWidth,
        const ProcessSnapshot& snapshot,
        const std::vector<DisplayRow>& rows,
        const AppOptions& options,
        const UiState& ui
    ) {
        std::string message = ui.message.text;
        const char* color = ui.message.ttlFrames > 0 ? notificationColor(ui.message.kind) : Ansi::Dim;
        if (message.empty()) {
            if (options.filter.empty()) {
                message = "ready";
            } else if (rows.empty()) {
                message = "no filter matches for \"" + options.filter + "\"";
                color = Ansi::Orange;
            } else {
                message = "filter active: " + options.filter;
            }
        }

        std::ostringstream status;
        status << "rows " << (rows.empty() ? 0 : ui.selectedIndex + 1) << "/" << rows.size()
               << " | pids " << snapshot.processes.size()
               << " | focus " << (ui.focusPane == FocusPane::ProcessList ? "left" : "right")
               << " | selected " << (ui.selectionActive ? std::to_string(ui.selectedPid) : std::string("none"))
               << " | path offset " << ui.pathScroll;
        if (ui.sortOrderPinned) {
            status << " | order pinned";
        }
        status
               << " | " << message;
        printBoxLine(height, 1, leftWidth, status.str(), color);
    }

    struct HelpRow {
        std::string keys;
        std::string text;
    };

    static void renderHelpScreen(int width, int height) {
        std::cout << "\x1b[?25l\x1b[H";
        for (int row = 1; row <= height; ++row) {
            printBoxLine(row, 1, width, "");
        }

        printBoxLine(1, 1, width, std::string(AppName) + " help", Ansi::Cyan);
        printBoxLine(2, 1, width, "F1/? close help | Esc back | 1 processes | 2 " + StartupAreaName() + " | 3 drivers", Ansi::Dim);
        printBoxLine(4, 1, width, "Hunt mode", Ansi::Orange);
        printBoxLine(5, 1, width, "x arms hunt on the focused row/member. h toggles hunt on the selected process.", Ansi::Dim);
        printBoxLine(6, 1, width, "It watches CPU >= 18%, memory jumps >= 80 MB, missing PID, and same-name PID reacquire.", Ansi::Dim);
        printBoxLine(7, 1, width, "Alerts are published internally and can be exported to SIEM NDJSON and Prometheus text metrics.", Ansi::Dim);
        printBoxLine(9, 1, width, "Integration/API surface", Ansi::Orange);
        printBoxLine(10, 1, width, "--rules FILE loads scalable rules: Name field op value", Ansi::Dim);
        printBoxLine(11, 1, width, "--siem-events FILE appends JSON events; --prometheus-file FILE writes scrapeable metrics.", Ansi::Dim);

        std::vector<HelpRow> rows;
        for (const auto& command : CommandRegistry()) {
            rows.push_back({ command.keys, command.description });
        }

        const int availableRows = std::max(1, height - 14);
        const int half = static_cast<int>((rows.size() + 1) / 2);
        const bool twoColumns = width >= 88 && availableRows >= half;
        const int contentTop = 13;

        if (twoColumns) {
            const int gap = 2;
            const int columnWidth = (width - 2 - gap) / 2;
            for (int i = 0; i < half; ++i) {
                printHelpRow(contentTop + i, 1, columnWidth, rows[static_cast<std::size_t>(i)]);
                const int other = i + half;
                if (other < static_cast<int>(rows.size())) {
                    printHelpRow(contentTop + i, 1 + columnWidth + gap, columnWidth, rows[static_cast<std::size_t>(other)]);
                }
            }
        } else {
            const int count = std::min(availableRows, static_cast<int>(rows.size()));
            for (int i = 0; i < count; ++i) {
                printHelpRow(contentTop + i, 1, width, rows[static_cast<std::size_t>(i)]);
            }
            if (count < static_cast<int>(rows.size())) {
                printBoxLine(height, 1, width, "make the console taller/wider for all shortcuts", Ansi::Orange);
            }
        }
        std::cout << "\x1b[J";
    }

    static void printHelpRow(int row, int col, int width, const HelpRow& item) {
        std::ostringstream line;
        line << std::left << std::setw(15) << item.keys << item.text;
        printBoxLine(row, col, width, line.str(), Ansi::White);
    }
};

class CommandDispatcher {
public:
    CommandDispatcher(Renderer& renderer, SnapshotExporter& exporter, IntegrationHub& hub)
        : renderer_(renderer), exporter_(exporter), hub_(hub) {}

    bool dispatch(Command command, AppOptions& options, UiState& ui, const ProcessSnapshot& snapshot) {
        if (command == Command::None) {
            return true;
        }

        if (ui.showHelp && command != Command::ToggleHelp && command != Command::Back && command != Command::Quit) {
            ui.showHelp = false;
        }

        if (ui.confirmKill && command != Command::ConfirmYes && command != Command::ConfirmNo && command != Command::Back) {
            ui.notify(NotificationKind::Warning, "kill pending: press y to confirm or n to cancel");
            return true;
        }

        switch (command) {
        case Command::Quit:
            return false;
        case Command::MoveUp:
            moveSelection(ui, snapshot, options, -1);
            break;
        case Command::MoveDown:
            moveSelection(ui, snapshot, options, 1);
            break;
        case Command::PageUp:
            moveSelection(ui, snapshot, options, -renderer_.maxRows(options));
            break;
        case Command::PageDown:
            moveSelection(ui, snapshot, options, renderer_.maxRows(options));
            break;
        case Command::JumpTop:
            jumpSelection(ui, snapshot, options, false);
            break;
        case Command::JumpBottom:
            jumpSelection(ui, snapshot, options, true);
            break;
        case Command::ScrollPathLeft:
            ui.pathScroll = std::max(0, ui.pathScroll - 4);
            break;
        case Command::ScrollPathRight:
            ui.pathScroll += 4;
            break;
        case Command::FocusNextPane:
            toggleFocusPane(ui, snapshot, options);
            break;
        case Command::ActivateSelection:
            activateFocusedItem(ui, snapshot, options);
            break;
        case Command::Deselect:
            if (ui.activeTab == AppTab::Processes) {
                deselect(ui);
            } else {
                deselectSystem(ui);
            }
            break;
        case Command::Back:
            handleBack(ui);
            break;
        case Command::NextRightPaneMode:
            cycleRightPaneMode(ui, true);
            break;
        case Command::PrevRightPaneMode:
            cycleRightPaneMode(ui, false);
            break;
        case Command::HuntFocused:
            huntFocused(ui, snapshot, options);
            break;
        case Command::SubtreeFocused:
            subtreeFocused(ui, snapshot, options);
            break;
        case Command::ToggleHelp:
            ui.showHelp = !ui.showHelp;
            break;
        case Command::CycleView:
            clearLiveSortHold(ui);
            options.viewMode = nextViewMode(options.viewMode);
            if (ui.activeTab == AppTab::Processes) {
                preserveSelection(ui, snapshot, options);
            }
            hub_.publish(EventType::ViewChanged, ui.selectedPid, "view: " + ViewName(options.viewMode));
            ui.notify(NotificationKind::Info, "view changed to " + ViewName(options.viewMode));
            break;
        case Command::CycleSort:
            clearLiveSortHold(ui);
            options.sortMode = nextSortMode(options.sortMode);
            if (ui.activeTab == AppTab::Processes) {
                preserveSelection(ui, snapshot, options);
            }
            ui.notify(NotificationKind::Info, "sort changed to " + SortName(options.sortMode));
            break;
        case Command::PromptFilter:
            promptFilter(options, ui);
            if (ui.activeTab == AppTab::Processes) {
                preserveSelection(ui, snapshot, options);
            } else {
                saveTabCursor(ui);
            }
            hub_.publish(EventType::FilterChanged, ui.selectedPid, "filter: " + options.filter);
            break;
        case Command::ClearContext:
            options.filter.clear();
            options.subtreePid = 0;
            ui.pathScroll = 0;
            ui.rightSelectedIndex = 0;
            ui.rightScroll = 0;
            clearLiveSortHold(ui);
            if (ui.activeTab == AppTab::Processes) {
                preserveSelection(ui, snapshot, options);
            } else {
                ui.scroll = 0;
                ui.selectedIndex = 0;
                ui.systemSelectionActive = false;
                ui.selectedSystemKey.clear();
                saveTabCursor(ui);
            }
            ui.notify(NotificationKind::Info, "filter/subtree cleared");
            break;
        case Command::PromptSubtree:
            promptSubtree(options, ui, snapshot);
            break;
        case Command::RequestKill:
            requestKill(ui, snapshot);
            break;
        case Command::ConfirmYes:
            confirmKill(ui);
            break;
        case Command::ConfirmNo:
            cancelKill(ui);
            break;
        case Command::ToggleHunt:
            toggleHunt(ui, snapshot, options);
            break;
        case Command::ShowProcessTab:
            switchTab(ui, AppTab::Processes);
            break;
        case Command::ShowRegistryTab:
            switchTab(ui, AppTab::Registry);
            break;
        case Command::ShowDriversTab:
            switchTab(ui, AppTab::Drivers);
            break;
        case Command::FasterRefresh:
            options.refreshMs = std::max(50, options.refreshMs - 50);
            ui.notify(NotificationKind::Info, "refresh " + std::to_string(options.refreshMs) + "ms");
            break;
        case Command::SlowerRefresh:
            options.refreshMs = std::min(5000, options.refreshMs + 50);
            ui.notify(NotificationKind::Info, "refresh " + std::to_string(options.refreshMs) + "ms");
            break;
        case Command::TogglePause:
            ui.paused = !ui.paused;
            ui.notify(NotificationKind::Info, ui.paused ? "paused" : "live refresh resumed");
            break;
        case Command::ExportSnapshot:
            exportSnapshot(snapshot, options, ui);
            break;
        case Command::None:
            break;
        }
        return true;
    }

private:
    static SortMode nextSortMode(SortMode current) {
        switch (current) {
        case SortMode::Cpu: return SortMode::Memory;
        case SortMode::Memory: return SortMode::Pid;
        case SortMode::Pid: return SortMode::Name;
        case SortMode::Name: return SortMode::Cpu;
        }
        return SortMode::Cpu;
    }

    static ViewMode nextViewMode(ViewMode current) {
        switch (current) {
        case ViewMode::Table: return ViewMode::Tree;
        case ViewMode::Tree: return ViewMode::Kernel;
        case ViewMode::Kernel: return ViewMode::Table;
        }
        return ViewMode::Table;
    }

    static void clearLiveSortHold(UiState& ui) {
        ui.sortOrderPinned = false;
        ui.heldRowOrder.clear();
    }

    static void holdLiveSort(UiState& ui, const std::vector<DisplayRow>& rows, const AppOptions& options) {
        if (options.viewMode == ViewMode::Tree || (options.sortMode != SortMode::Cpu && options.sortMode != SortMode::Memory)) {
            clearLiveSortHold(ui);
            return;
        }

        ui.heldRowOrder.clear();
        ui.heldRowOrder.reserve(rows.size());
        for (const auto& row : rows) {
            ui.heldRowOrder.push_back(row.pid);
        }

        ui.sortOrderPinned = true;
    }

    int systemTabCount(const ProcessSnapshot& snapshot, const AppOptions& options, AppTab tab) const {
        return static_cast<int>(renderer_.systemEntriesForActions(snapshot, options, tab).size());
    }

    static void saveTabCursor(UiState& ui) {
        switch (ui.activeTab) {
        case AppTab::Processes:
            ui.processSelectedIndex = ui.selectedIndex;
            ui.processScroll = ui.scroll;
            break;
        case AppTab::Registry:
            ui.startupSelectedIndex = ui.selectedIndex;
            ui.startupScroll = ui.scroll;
            break;
        case AppTab::Drivers:
            ui.driverSelectedIndex = ui.selectedIndex;
            ui.driverScroll = ui.scroll;
            break;
        }
    }

    static void restoreTabCursor(UiState& ui) {
        switch (ui.activeTab) {
        case AppTab::Processes:
            ui.selectedIndex = ui.processSelectedIndex;
            ui.scroll = ui.processScroll;
            break;
        case AppTab::Registry:
            ui.selectedIndex = ui.startupSelectedIndex;
            ui.scroll = ui.startupScroll;
            break;
        case AppTab::Drivers:
            ui.selectedIndex = ui.driverSelectedIndex;
            ui.scroll = ui.driverScroll;
            break;
        }
    }

    static void switchTab(UiState& ui, AppTab tab) {
        saveTabCursor(ui);
        ui.activeTab = tab;
        ui.focusPane = FocusPane::ProcessList;
        restoreTabCursor(ui);
        ui.rightSelectedIndex = 0;
        ui.rightScroll = 0;
        if (tab != AppTab::Processes) {
            clearLiveSortHold(ui);
        }
        ui.notify(NotificationKind::Info, "tab: " + TabName(tab));
    }

    static RightPaneMode nextRightPaneMode(RightPaneMode current, bool forward) {
        if (forward) {
            switch (current) {
            case RightPaneMode::Members: return RightPaneMode::Details;
            case RightPaneMode::Details: return RightPaneMode::Children;
            case RightPaneMode::Children: return RightPaneMode::Services;
            case RightPaneMode::Services: return RightPaneMode::Drivers;
            case RightPaneMode::Drivers: return RightPaneMode::Registry;
            case RightPaneMode::Registry: return RightPaneMode::Members;
            }
        } else {
            switch (current) {
            case RightPaneMode::Members: return RightPaneMode::Registry;
            case RightPaneMode::Details: return RightPaneMode::Members;
            case RightPaneMode::Children: return RightPaneMode::Details;
            case RightPaneMode::Services: return RightPaneMode::Children;
            case RightPaneMode::Drivers: return RightPaneMode::Services;
            case RightPaneMode::Registry: return RightPaneMode::Drivers;
            }
        }
        return RightPaneMode::Members;
    }

    void moveSelection(UiState& ui, const ProcessSnapshot& snapshot, const AppOptions& options, int delta) {
        if (ui.activeTab != AppTab::Processes) {
            const int count = systemTabCount(snapshot, options, ui.activeTab);
            if (count == 0) {
                ui.selectedIndex = 0;
                ui.scroll = 0;
                return;
            }
            ui.selectedIndex = std::max(0, std::min(ui.selectedIndex + delta, count - 1));
            return;
        }
        if (ui.focusPane == FocusPane::GroupMembers) {
            moveRightSelection(ui, snapshot, options, delta);
            return;
        }

        const auto rows = renderer_.rowsForActions(snapshot.processes, options, ui);
        if (rows.empty()) {
            ui.selectedIndex = 0;
            ui.selectedPid = 0;
            ui.selectionActive = false;
            ui.notify(NotificationKind::Warning, "no rows to select");
            return;
        }

        holdLiveSort(ui, rows, options);
        ui.selectedIndex = std::max(0, std::min(ui.selectedIndex + delta, static_cast<int>(rows.size()) - 1));
        ui.selectedPid = rows[static_cast<std::size_t>(ui.selectedIndex)].pid;
        ui.selectionActive = true;
        ui.rightSelectedIndex = 0;
        ui.rightScroll = 0;
    }

    void moveRightSelection(UiState& ui, const ProcessSnapshot& snapshot, const AppOptions& options, int delta) {
        if (!ui.selectionActive) {
            ui.notify(NotificationKind::Warning, "select a process before using the right pane");
            return;
        }
        if (ui.rightPaneMode == RightPaneMode::Services || ui.rightPaneMode == RightPaneMode::Drivers || ui.rightPaneMode == RightPaneMode::Registry) {
            const auto entries = renderer_.rightSystemEntriesForActions(snapshot, options, ui.rightPaneMode);
            if (entries.empty()) {
                ui.rightSelectedIndex = 0;
                ui.rightScroll = 0;
                ui.notify(NotificationKind::Warning, "right pane has no filtered entries");
                return;
            }
            ui.rightSelectedIndex = std::max(0, std::min(ui.rightSelectedIndex + delta, static_cast<int>(entries.size()) - 1));
            return;
        }
        if (ui.rightPaneMode == RightPaneMode::Details) {
            ui.notify(NotificationKind::Info, "details pane has no list; use [ or ]");
            return;
        }

        const auto members = renderer_.rightPaneItemsForActions(snapshot.processes, options, ui);
        if (members.empty()) {
            ui.rightSelectedIndex = 0;
            ui.rightScroll = 0;
            ui.notify(NotificationKind::Warning, "selected group has no visible members");
            return;
        }

        ui.rightSelectedIndex = std::max(0, std::min(ui.rightSelectedIndex + delta, static_cast<int>(members.size()) - 1));
    }

    void jumpSelection(UiState& ui, const ProcessSnapshot& snapshot, const AppOptions& options, bool bottom) {
        if (ui.activeTab != AppTab::Processes) {
            const int count = systemTabCount(snapshot, options, ui.activeTab);
            ui.selectedIndex = count == 0 ? 0 : (bottom ? count - 1 : 0);
            return;
        }
        if (ui.focusPane == FocusPane::GroupMembers) {
            if (ui.rightPaneMode == RightPaneMode::Services || ui.rightPaneMode == RightPaneMode::Drivers || ui.rightPaneMode == RightPaneMode::Registry) {
                const auto entries = renderer_.rightSystemEntriesForActions(snapshot, options, ui.rightPaneMode);
                if (entries.empty()) {
                    ui.rightSelectedIndex = 0;
                    ui.rightScroll = 0;
                    ui.notify(NotificationKind::Warning, "right pane has no filtered entries");
                    return;
                }
                ui.rightSelectedIndex = bottom ? static_cast<int>(entries.size()) - 1 : 0;
                ui.notify(NotificationKind::Info, bottom ? "right pane: bottom" : "right pane: top");
                return;
            }
            const auto members = renderer_.rightPaneItemsForActions(snapshot.processes, options, ui);
            if (members.empty()) {
                ui.rightSelectedIndex = 0;
                ui.rightScroll = 0;
                ui.notify(NotificationKind::Warning, "right pane has no members");
                return;
            }
            ui.rightSelectedIndex = bottom ? static_cast<int>(members.size()) - 1 : 0;
            ui.notify(NotificationKind::Info, bottom ? "right pane: bottom" : "right pane: top");
            return;
        }

        const auto rows = renderer_.rowsForActions(snapshot.processes, options, ui);
        if (rows.empty()) {
            ui.selectedIndex = 0;
            ui.selectedPid = 0;
            ui.selectionActive = false;
            ui.notify(NotificationKind::Warning, "no rows to jump through");
            return;
        }

        holdLiveSort(ui, rows, options);
        ui.selectedIndex = bottom ? static_cast<int>(rows.size()) - 1 : 0;
        ui.selectedPid = rows[static_cast<std::size_t>(ui.selectedIndex)].pid;
        ui.selectionActive = true;
        ui.rightSelectedIndex = 0;
        ui.rightScroll = 0;
        ui.notify(NotificationKind::Info, bottom ? "process list: bottom" : "process list: top");
    }

    static void handleBack(UiState& ui) {
        if (ui.showHelp) {
            ui.showHelp = false;
            ui.notify(NotificationKind::Info, "help closed");
            return;
        }
        if (ui.confirmKill) {
            cancelKill(ui);
            return;
        }
        if (ui.focusPane == FocusPane::GroupMembers) {
            ui.focusPane = FocusPane::ProcessList;
            ui.notify(NotificationKind::Info, "back to process list");
            return;
        }
        if (ui.activeTab != AppTab::Processes) {
            if (ui.systemSelectionActive && ui.selectedSystemTab == ui.activeTab) {
                deselectSystem(ui);
                return;
            }
            ui.notify(NotificationKind::Info, "nothing selected in " + TabName(ui.activeTab));
            return;
        }
        if (ui.selectionActive) {
            deselect(ui);
            return;
        }
        ui.notify(NotificationKind::Info, "nothing to go back from");
    }

    void cycleRightPaneMode(UiState& ui, bool forward) {
        ui.rightPaneMode = nextRightPaneMode(ui.rightPaneMode, forward);
        ui.rightSelectedIndex = 0;
        ui.rightScroll = 0;
        ui.notify(NotificationKind::Info, "right pane: " + RightPaneModeName(ui.rightPaneMode));
    }

    DWORD focusedPid(const UiState& ui, const ProcessSnapshot& snapshot, const AppOptions& options) {
        if (ui.focusPane == FocusPane::GroupMembers && ui.rightPaneMode != RightPaneMode::Details) {
            if (ui.rightPaneMode == RightPaneMode::Services || ui.rightPaneMode == RightPaneMode::Drivers || ui.rightPaneMode == RightPaneMode::Registry) {
                const auto entries = renderer_.rightSystemEntriesForActions(snapshot, options, ui.rightPaneMode);
                if (!entries.empty()) {
                    const int index = std::max(0, std::min(ui.rightSelectedIndex, static_cast<int>(entries.size()) - 1));
                    return entries[static_cast<std::size_t>(index)].pid;
                }
                return 0;
            }
            const auto items = renderer_.rightPaneItemsForActions(snapshot.processes, options, ui);
            if (!items.empty()) {
                const int index = std::max(0, std::min(ui.rightSelectedIndex, static_cast<int>(items.size()) - 1));
                return items[static_cast<std::size_t>(index)].pid;
            }
        }
        return ui.selectionActive ? ui.selectedPid : 0;
    }

    void huntFocused(UiState& ui, const ProcessSnapshot& snapshot, const AppOptions& options) {
        const DWORD pid = focusedPid(ui, snapshot, options);
        if (pid == 0) {
            ui.notify(NotificationKind::Warning, "nothing focused to hunt");
            return;
        }
        selectPid(ui, snapshot, options, pid);
        toggleHunt(ui, snapshot, options);
    }

    void subtreeFocused(UiState& ui, const ProcessSnapshot& snapshot, AppOptions& options) {
        const DWORD pid = focusedPid(ui, snapshot, options);
        if (pid == 0 || !pidExists(snapshot, pid)) {
            ui.notify(NotificationKind::Warning, "nothing focused for subtree");
            return;
        }
        options.subtreePid = pid;
        options.viewMode = ViewMode::Tree;
        selectPid(ui, snapshot, options, pid);
        ui.focusPane = FocusPane::ProcessList;
        ui.notify(NotificationKind::Success, "subtree changed to PID " + std::to_string(pid));
    }

    void preserveSelection(UiState& ui, const ProcessSnapshot& snapshot, const AppOptions& options) {
        const DWORD oldPid = ui.selectedPid;
        const auto rows = renderer_.rowsForActions(snapshot.processes, options, ui);
        if (rows.empty()) {
            ui.selectedIndex = 0;
            ui.selectedPid = 0;
            ui.selectionActive = false;
            return;
        }

        if (ui.selectionActive) {
            for (int i = 0; i < static_cast<int>(rows.size()); ++i) {
                if (rows[static_cast<std::size_t>(i)].pid == oldPid) {
                    ui.selectedIndex = i;
                    ui.selectedPid = oldPid;
                    return;
                }
            }
        }
        ui.selectedIndex = std::min(ui.selectedIndex, static_cast<int>(rows.size()) - 1);
        if (ui.selectionActive) {
            ui.selectedPid = rows[static_cast<std::size_t>(ui.selectedIndex)].pid;
        }
    }

    void selectPid(UiState& ui, const ProcessSnapshot& snapshot, const AppOptions& options, DWORD pid) {
        const auto rows = renderer_.rowsForActions(snapshot.processes, options, ui);
        holdLiveSort(ui, rows, options);
        for (int i = 0; i < static_cast<int>(rows.size()); ++i) {
            if (rows[static_cast<std::size_t>(i)].pid == pid) {
                ui.selectedIndex = i;
                ui.selectedPid = pid;
                ui.selectionActive = true;
                ui.rightSelectedIndex = 0;
                ui.rightScroll = 0;
                return;
            }
        }
        ui.selectedPid = pid;
        ui.selectionActive = true;
        ui.rightSelectedIndex = 0;
        ui.rightScroll = 0;
    }

    void toggleFocusPane(UiState& ui, const ProcessSnapshot& snapshot, const AppOptions& options) {
        if (ui.focusPane == FocusPane::ProcessList) {
            if (ConsoleWindow::width() < 112) {
                ui.notify(NotificationKind::Info, "widen the window to show the right pane");
                return;
            }
            if (!ui.selectionActive) {
                ui.notify(NotificationKind::Warning, "select a process before opening the right pane");
                return;
            }
            if (ui.rightPaneMode != RightPaneMode::Details) {
                const bool systemMode = ui.rightPaneMode == RightPaneMode::Services || ui.rightPaneMode == RightPaneMode::Drivers || ui.rightPaneMode == RightPaneMode::Registry;
                const bool hasItems = systemMode
                    ? !renderer_.rightSystemEntriesForActions(snapshot, options, ui.rightPaneMode).empty()
                    : !renderer_.rightPaneItemsForActions(snapshot.processes, options, ui).empty();
                if (!hasItems) {
                    ui.notify(NotificationKind::Warning, "right pane has no visible items");
                }
            }
            ui.focusPane = FocusPane::GroupMembers;
            ui.notify(NotificationKind::Info, "right pane active");
        } else {
            ui.focusPane = FocusPane::ProcessList;
            ui.notify(NotificationKind::Info, "process list active");
        }
    }

    void activateFocusedItem(UiState& ui, const ProcessSnapshot& snapshot, const AppOptions& options) {
        if (ui.activeTab != AppTab::Processes) {
            const auto entries = renderer_.systemEntriesForActions(snapshot, options, ui.activeTab);
            if (entries.empty()) {
                ui.systemSelectionActive = false;
                ui.notify(NotificationKind::Warning, "nothing in " + TabName(ui.activeTab) + " tab to select");
                return;
            }

            ui.selectedIndex = std::max(0, std::min(ui.selectedIndex, static_cast<int>(entries.size()) - 1));
            const auto& entry = entries[static_cast<std::size_t>(ui.selectedIndex)];
            ui.selectedSystemTab = ui.activeTab;
            ui.selectedSystemKey = entry.type + ":" + entry.name;
            ui.systemSelectionActive = true;
            saveTabCursor(ui);
            ui.notify(NotificationKind::Success, "selected " + TabName(ui.activeTab) + ": " + entry.name);
            return;
        }

        if (ui.focusPane == FocusPane::GroupMembers) {
            if (ui.rightPaneMode == RightPaneMode::Services || ui.rightPaneMode == RightPaneMode::Drivers || ui.rightPaneMode == RightPaneMode::Registry) {
                const auto entries = renderer_.rightSystemEntriesForActions(snapshot, options, ui.rightPaneMode);
                if (entries.empty()) {
                    ui.notify(NotificationKind::Warning, "nothing in right pane to select");
                    return;
                }
                ui.rightSelectedIndex = std::max(0, std::min(ui.rightSelectedIndex, static_cast<int>(entries.size()) - 1));
                const DWORD pid = entries[static_cast<std::size_t>(ui.rightSelectedIndex)].pid;
                if (pid == 0 || !pidExists(snapshot, pid)) {
                    ui.notify(NotificationKind::Info, "entry has no live process PID");
                    return;
                }
                selectPid(ui, snapshot, options, pid);
                ui.notify(NotificationKind::Success, "selected PID " + std::to_string(ui.selectedPid));
                return;
            }
            if (ui.rightPaneMode == RightPaneMode::Details) {
                ui.notify(NotificationKind::Info, "details pane already follows selection");
                return;
            }
            const auto members = renderer_.rightPaneItemsForActions(snapshot.processes, options, ui);
            if (members.empty()) {
                ui.notify(NotificationKind::Warning, "nothing in right pane to select");
                return;
            }
            ui.rightSelectedIndex = std::max(0, std::min(ui.rightSelectedIndex, static_cast<int>(members.size()) - 1));
            selectPid(ui, snapshot, options, members[static_cast<std::size_t>(ui.rightSelectedIndex)].pid);
            ui.notify(NotificationKind::Success, "selected PID " + std::to_string(ui.selectedPid));
            return;
        }

        const auto rows = renderer_.rowsForActions(snapshot.processes, options, ui);
        if (rows.empty()) {
            ui.notify(NotificationKind::Warning, "nothing to select");
            return;
        }
        ui.selectedIndex = std::max(0, std::min(ui.selectedIndex, static_cast<int>(rows.size()) - 1));
        holdLiveSort(ui, rows, options);
        ui.selectedPid = rows[static_cast<std::size_t>(ui.selectedIndex)].pid;
        ui.selectionActive = true;
        ui.rightSelectedIndex = 0;
        ui.rightScroll = 0;
        ui.notify(NotificationKind::Success, "selected PID " + std::to_string(ui.selectedPid));
    }

    static void deselect(UiState& ui) {
        ui.selectionActive = false;
        ui.selectedPid = 0;
        ui.rightSelectedIndex = 0;
        ui.rightScroll = 0;
        ui.focusPane = FocusPane::ProcessList;
        clearLiveSortHold(ui);
        ui.notify(NotificationKind::Info, "selection cleared");
    }

    static void deselectSystem(UiState& ui) {
        ui.systemSelectionActive = false;
        ui.selectedSystemKey.clear();
        ui.notify(NotificationKind::Info, TabName(ui.activeTab) + " selection cleared");
    }

    static void promptFilter(AppOptions& options, UiState& ui) {
        options.filter = ReadPromptLine("filter (name, pid, path, service, startup, driver; empty clears) > ");
        ui.scroll = 0;
        ui.rightSelectedIndex = 0;
        ui.rightScroll = 0;
        clearLiveSortHold(ui);
        ui.notify(NotificationKind::Success, options.filter.empty() ? "filter cleared" : "filter applied: " + options.filter);
    }

    static bool pidExists(const ProcessSnapshot& snapshot, DWORD pid) {
        for (const auto& process : snapshot.processes) {
            if (process.pid == pid) {
                return true;
            }
        }
        return false;
    }

    static void promptSubtree(AppOptions& options, UiState& ui, const ProcessSnapshot& snapshot) {
        const std::string input = ReadPromptLine("subtree PID (0 clears) > ");

        std::istringstream parser(input);
        DWORD pid = 0;
        parser >> pid;
        if (pid != 0 && !pidExists(snapshot, pid)) {
            ui.notify(NotificationKind::Error, "PID not found: " + std::to_string(pid));
            return;
        }

        options.subtreePid = pid;
        options.viewMode = ViewMode::Tree;
        ui.scroll = 0;
        ui.selectedPid = pid;
        ui.notify(NotificationKind::Success, pid == 0 ? "subtree cleared" : "subtree changed to PID " + std::to_string(pid));
    }

    void requestKill(UiState& ui, const ProcessSnapshot& snapshot) {
        if (!ui.selectionActive) {
            ui.notify(NotificationKind::Warning, "select a process before killing");
            return;
        }
        if (ui.selectedPid == 0 || ui.selectedPid == 4) {
            ui.notify(NotificationKind::Error, "refusing to kill protected PID " + std::to_string(ui.selectedPid));
            return;
        }
        if (!pidExists(snapshot, ui.selectedPid)) {
            ui.notify(NotificationKind::Error, "selected PID no longer exists");
            return;
        }

        ui.confirmKill = true;
        ui.pendingKillPid = ui.selectedPid;
        ui.notify(NotificationKind::Warning, "kill PID " + std::to_string(ui.pendingKillPid) + "? press y/n", 60);
    }

    void confirmKill(UiState& ui) {
        if (!ui.confirmKill) {
            return;
        }

        const DWORD pid = ui.pendingKillPid;
        ui.confirmKill = false;
        ui.pendingKillPid = 0;
        ui.killRequested.insert(pid);

#ifdef _WIN32
        HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (!process) {
            const std::string error = FormatLastError();
            ui.notify(NotificationKind::Error, "kill failed: " + error, 40);
            hub_.publish(EventType::KillFailed, pid, error);
            return;
        }

        if (TerminateProcess(process, 1)) {
            ui.notify(NotificationKind::Success, "kill requested for PID " + std::to_string(pid));
            hub_.publish(EventType::ProcessKilled, pid, "terminate requested");
        } else {
            const std::string error = FormatLastError();
            ui.notify(NotificationKind::Error, "kill failed: " + error, 40);
            hub_.publish(EventType::KillFailed, pid, error);
        }
        CloseHandle(process);
#else
        if (::kill(static_cast<pid_t>(pid), SIGTERM) == 0) {
            ui.notify(NotificationKind::Success, "SIGTERM sent to PID " + std::to_string(pid));
            hub_.publish(EventType::ProcessKilled, pid, "SIGTERM requested");
        } else {
            const std::string error = FormatLastError(errno);
            ui.notify(NotificationKind::Error, "kill failed: " + error, 40);
            hub_.publish(EventType::KillFailed, pid, error);
        }
#endif
    }

    static void cancelKill(UiState& ui) {
        if (ui.confirmKill) {
            ui.notify(NotificationKind::Info, "kill cancelled");
        }
        ui.confirmKill = false;
        ui.pendingKillPid = 0;
    }

    static void toggleHunt(UiState& ui, const ProcessSnapshot& snapshot, const AppOptions& options) {
        const auto rows = Renderer().rowsForActions(snapshot.processes, options, ui);
        if (rows.empty() || !ui.selectionActive) {
            ui.notify(NotificationKind::Warning, "nothing selected to hunt");
            return;
        }

        const ProcessInfo* selected = nullptr;
        for (const auto& process : snapshot.processes) {
            if (process.pid == ui.selectedPid) {
                selected = &process;
                break;
            }
        }
        if (!selected) {
            ui.notify(NotificationKind::Error, "selected PID is not live");
            return;
        }

        if (ui.hunt.active && ui.hunt.pid == selected->pid) {
            ui.hunt = HuntState{};
            ui.notify(NotificationKind::Info, "hunt disabled");
            return;
        }

        ui.hunt.active = true;
        ui.hunt.pid = selected->pid;
        ui.hunt.name = selected->name;
        ui.hunt.lastWorkingSet = selected->workingSet;
        ui.hunt.peakWorkingSet = selected->workingSet;
        ui.hunt.lastCpu = selected->cpu;
        ui.hunt.peakCpu = selected->cpu;
        ui.hunt.alert.clear();
        ui.hunt.status = "watching PID " + std::to_string(selected->pid);
        ui.hunt.missingFrames = 0;
        ui.notify(NotificationKind::Success, "hunt armed for PID " + std::to_string(selected->pid));
    }

    void exportSnapshot(const ProcessSnapshot& snapshot, const AppOptions& options, UiState& ui) {
        const std::string path = "cliprocster_snapshot.json";
        std::string error;
        const auto dto = SnapshotDtoFactory::make(snapshot, options, ui);
        if (exporter_.exportSnapshot(dto, path, error)) {
            ui.notify(NotificationKind::Success, "exported " + path);
            hub_.publish(EventType::SnapshotExported, ui.selectedPid, path);
        } else {
            ui.notify(NotificationKind::Error, "export failed: " + error);
        }
    }

    Renderer& renderer_;
    SnapshotExporter& exporter_;
    IntegrationHub& hub_;
};

class App {
public:
    int run(int argc, char* argv[]) {
        ConsoleWindow::enableVirtualTerminal();

        if (!parseArgs(argc, argv)) {
            return 0;
        }
        loadRulesIfConfigured();
        startApiIfConfigured();

        if (options_.once) {
            std::cout << "\x1b[2J";
            repository_.refresh(options_, false);
            std::this_thread::sleep_for(std::chrono::milliseconds(std::max(100, options_.refreshMs)));
            auto snapshot = repository_.refresh(options_, false);
            history_.update(repository_.previous(), snapshot, hub_);
            hunt_.update(ui_, snapshot.processes, hub_);
            alertRules_.evaluate(snapshot, ui_, hub_);
            integrations_.writeEvents(hub_, options_.siemEventsPath);
            integrations_.writePrometheus(snapshot, ui_, alertRules_, hub_, options_.prometheusPath, &history_);
            api_.publish(snapshot, options_, ui_, alertRules_, hub_, history_);
            const auto rows = renderer_.rowsForActions(snapshot.processes, options_, ui_);
            if (ui_.selectedPid == 0 && !rows.empty()) {
                ui_.selectedIndex = 0;
                ui_.selectedPid = rows.front().pid;
                ui_.selectionActive = true;
            }
            if (!options_.exportPath.empty()) {
                std::string error;
                const auto dto = SnapshotDtoFactory::make(snapshot, options_, ui_);
                if (exporter_.exportSnapshot(dto, options_.exportPath, error)) {
                    ui_.notify(NotificationKind::Success, "exported " + options_.exportPath);
                    hub_.publish(EventType::SnapshotExported, ui_.selectedPid, options_.exportPath);
                } else {
                    ui_.notify(NotificationKind::Error, "export failed: " + error);
                }
            }
            renderer_.render(snapshot, options_, ui_);
            std::cout << "\x1b[?25h\n";
            return 0;
        }

        std::cout << "\x1b[?1049h\x1b[2J\x1b[H";
        ConsoleSize lastSize = ConsoleWindow::size();
        bool running = true;
        while (running) {
            const ConsoleSize currentSize = ConsoleWindow::size();
            if (currentSize != lastSize) {
                std::cout << "\x1b[2J\x1b[H";
                lastSize = currentSize;
            }

            const bool modalOpen = ui_.showHelp || ui_.confirmKill;
            auto snapshot = repository_.refresh(options_, ui_.paused || modalOpen);
            if (!modalOpen) {
                updateGoneFade(snapshot.processes);
                history_.update(repository_.previous(), snapshot, hub_);
                hunt_.update(ui_, snapshot.processes, hub_);
                alertRules_.evaluate(snapshot, ui_, hub_);
                integrations_.writeEvents(hub_, options_.siemEventsPath);
                integrations_.writePrometheus(snapshot, ui_, alertRules_, hub_, options_.prometheusPath, &history_);
            }
            api_.publish(snapshot, options_, ui_, alertRules_, hub_, history_);
            renderer_.render(snapshot, options_, ui_);
            if (!modalOpen) {
                tickNotification();
            }

            if (modalOpen) {
                const Command command = waitForModalCommand(lastSize);
                if (command != Command::None) {
                    running = dispatcher_.dispatch(command, options_, ui_, repository_.current());
                }
                continue;
            }

            const int effectiveRefresh = modalOpen ? 1000 : options_.refreshMs;
            const int slices = std::max(1, effectiveRefresh / 25);
            const int sleepMs = std::max(10, effectiveRefresh / slices);
            for (int i = 0; i < slices; ++i) {
                Command command = input_.readCommand();
                if (command == Command::None) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
                    continue;
                }
                running = dispatcher_.dispatch(command, options_, ui_, repository_.current());
                break;
            }
        }

        std::cout << "\x1b[2J\x1b[H\x1b[?25h\x1b[?1049l";
        return 0;
    }

private:
    Command waitForModalCommand(ConsoleSize size) {
        for (;;) {
            const Command command = input_.readCommand();
            if (command != Command::None) {
                return command;
            }
            if (ConsoleWindow::size() != size) {
                return Command::None;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
    }

    void loadRulesIfConfigured() {
        if (options_.rulesPath.empty()) {
            return;
        }
        std::string error;
        if (alertRules_.load(options_.rulesPath, error)) {
            ui_.notify(NotificationKind::Success, "loaded alert rules: " + std::to_string(alertRules_.rules().size()));
        } else {
            if (options_.once) {
                std::cerr << "rules failed: " << error << "\n";
            }
            ui_.notify(NotificationKind::Error, "rules failed: " + error, 80);
        }
    }

    void startApiIfConfigured() {
        if (!options_.httpApi || options_.once) {
            return;
        }
        std::string error;
        if (api_.start(options_.httpBind, options_.httpPort, error)) {
            ui_.notify(NotificationKind::Success, "HTTP API http://" + options_.httpBind + ":" + std::to_string(options_.httpPort));
        } else {
            ui_.notify(NotificationKind::Error, "HTTP API failed: " + error, 80);
        }
    }

    static SortMode parseSort(std::string value) {
        value = ToLower(value);
        if (value == "mem" || value == "memory") {
            return SortMode::Memory;
        }
        if (value == "pid") {
            return SortMode::Pid;
        }
        if (value == "name") {
            return SortMode::Name;
        }
        return SortMode::Cpu;
    }

    static ViewMode parseView(std::string value) {
        value = ToLower(value);
        if (value == "tree") {
            return ViewMode::Tree;
        }
        if (value == "kernel") {
            return ViewMode::Kernel;
        }
        return ViewMode::Table;
    }

    static int parseInt(const std::string& value, int fallback) {
        std::istringstream parser(value);
        int result = fallback;
        parser >> result;
        return result;
    }

    static DWORD parsePid(const std::string& value) {
        std::istringstream parser(value);
        DWORD result = 0;
        parser >> result;
        return result;
    }

    static void renderHelpText() {
        std::cout
            << AppName << "\n"
            << "usage: CliProcster.exe [options]\n"
            << "  --once, -1                 render one frame and exit\n"
            << "  --view table|tree|kernel\n"
            << "  --sort cpu|memory|pid|name\n"
            << "  --filter TEXT, -f TEXT\n"
            << "  --pid PID                  tree view rooted at PID\n"
            << "  --hunt-pid PID             start hunt mode on PID\n"
            << "  --refresh MS               live refresh interval, default 200\n"
            << "  --limit N                  max rendered rows\n"
            << "  --include-kernel | --no-kernel\n"
            << "  --export-json FILE         export snapshot JSON and exit\n"
            << "  --rules FILE               load alert rules: Name field op value\n"
            << "                             fields include child_count and command_line\n"
            << "  --siem-events FILE         append NDJSON events for SIEM ingestion\n"
            << "  --prometheus-file FILE     write Prometheus textfile metrics\n"
            << "  --http-api                 serve /snapshot, /events, /metrics locally\n"
            << "  --http-bind ADDRESS        API bind address, default 127.0.0.1\n"
            << "  --http-port PORT           API port, default 8765\n"
            << "\n"
            << "keys:\n";
        for (const auto& command : CommandRegistry()) {
            std::cout << "  " << std::left << std::setw(18) << command.keys << command.description << "\n";
        }
    }

    bool parseArgs(int argc, char* argv[]) {
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--help" || arg == "-h" || arg == "/?") {
                renderHelpText();
                return false;
            }
            if (arg == "--once" || arg == "-1") {
                options_.once = true;
            } else if ((arg == "--filter" || arg == "-f") && i + 1 < argc) {
                options_.filter = argv[++i];
            } else if (arg == "--sort" && i + 1 < argc) {
                options_.sortMode = parseSort(argv[++i]);
            } else if (arg == "--view" && i + 1 < argc) {
                options_.viewMode = parseView(argv[++i]);
            } else if ((arg == "--pid" || arg == "--subtree") && i + 1 < argc) {
                options_.subtreePid = parsePid(argv[++i]);
                options_.viewMode = ViewMode::Tree;
            } else if (arg == "--hunt-pid" && i + 1 < argc) {
                ui_.hunt.active = true;
                ui_.hunt.pid = parsePid(argv[++i]);
            } else if (arg == "--refresh" && i + 1 < argc) {
                options_.refreshMs = std::max(50, parseInt(argv[++i], options_.refreshMs));
            } else if (arg == "--limit" && i + 1 < argc) {
                options_.rowLimit = std::max(0, parseInt(argv[++i], options_.rowLimit));
            } else if (arg == "--export-json" && i + 1 < argc) {
                options_.exportPath = argv[++i];
                options_.once = true;
            } else if (arg == "--rules" && i + 1 < argc) {
                options_.rulesPath = argv[++i];
            } else if (arg == "--siem-events" && i + 1 < argc) {
                options_.siemEventsPath = argv[++i];
            } else if (arg == "--prometheus-file" && i + 1 < argc) {
                options_.prometheusPath = argv[++i];
            } else if (arg == "--http-api") {
                options_.httpApi = true;
            } else if (arg == "--http-bind" && i + 1 < argc) {
                options_.httpBind = argv[++i];
                options_.httpApi = true;
            } else if (arg == "--http-port" && i + 1 < argc) {
                options_.httpPort = std::max(1, std::min(65535, parseInt(argv[++i], options_.httpPort)));
                options_.httpApi = true;
            } else if (arg == "--include-kernel") {
                options_.includeKernel = true;
            } else if (arg == "--no-kernel") {
                options_.includeKernel = false;
            }
        }
        return true;
    }

    void updateGoneFade(const std::vector<ProcessInfo>& current) {
        std::set<DWORD> currentPids;
        for (const auto& process : current) {
            currentPids.insert(process.pid);
        }

        for (const auto& process : repository_.previous().processes) {
            if (process.pid != 0 && currentPids.count(process.pid) == 0) {
                ui_.fadingGone[process.pid] = process;
                ui_.fadingAge[process.pid] = 0;
            }
        }

        std::vector<DWORD> finished;
        for (auto& item : ui_.fadingAge) {
            if (currentPids.count(item.first) != 0) {
                finished.push_back(item.first);
                continue;
            }
            item.second += 1;
            if (item.second > 14) {
                finished.push_back(item.first);
            }
        }

        for (DWORD pid : finished) {
            ui_.fadingAge.erase(pid);
            ui_.fadingGone.erase(pid);
            ui_.killRequested.erase(pid);
        }
    }

    void tickNotification() {
        if (ui_.message.ttlFrames > 0) {
            ui_.message.ttlFrames -= 1;
            if (ui_.message.ttlFrames == 0) {
                ui_.message.text.clear();
            }
        }
    }

    AppOptions options_;
    UiState ui_;
    ProcessRepository repository_;
    Renderer renderer_;
    InputController input_;
    JsonSnapshotExporter exporter_;
    IntegrationHub hub_;
    AlertRuleService alertRules_;
    IntegrationExporter integrations_;
    LocalHttpApi api_;
    HistoryTracker history_;
    HuntService hunt_;
    CommandDispatcher dispatcher_{ renderer_, exporter_, hub_ };
};

} // namespace

int main(int argc, char* argv[]) {
    App app;
    return app.run(argc, argv);
}
