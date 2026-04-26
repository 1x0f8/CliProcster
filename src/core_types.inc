
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
    int rightPathScroll = 0;
    Command repeatCommand = Command::None;
    int repeatCount = 0;
    std::chrono::steady_clock::time_point repeatAt{};
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
    case SortMode::Cpu: return "system CPU share";
    case SortMode::Memory: return "Memory";
    case SortMode::Pid: return "PID";
    case SortMode::Name: return "Name";
    }
    return "system CPU share";
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

bool TryFileSizeForFingerprint(const std::string& path, std::uint64_t& size) {
#ifdef _WIN32
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &data)) {
        return false;
    }
    size = (static_cast<std::uint64_t>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
    return true;
#else
    struct stat data {};
    if (stat(path.c_str(), &data) != 0) {
        return false;
    }
    size = static_cast<std::uint64_t>(data.st_size);
    return true;
#endif
}

std::string FastFileFingerprint(const std::string& path) {
    static std::unordered_map<std::string, std::string> cache;
    if (path.empty()) {
        return "unknown";
    }
    const auto cached = cache.find(path);
    if (cached != cache.end()) {
        return cached->second;
    }

    std::uint64_t size = 0;
    if (!TryFileSizeForFingerprint(path, size)) {
        cache[path] = "unknown";
        return cache[path];
    }

    std::uint64_t hash = 1469598103934665603ull;
    for (char c : path) {
        hash ^= static_cast<unsigned char>(c);
        hash *= 1099511628211ull;
    }
    for (char c : std::to_string(size)) {
        hash ^= static_cast<unsigned char>(c);
        hash *= 1099511628211ull;
    }

    std::ostringstream out;
    out << "fast-path-size-fnv1a64:" << std::hex << std::setw(16) << std::setfill('0') << hash;
    cache[path] = out.str();
    return cache[path];
}

std::string SigningCheckStateForPath(const std::string& path) {
    static std::unordered_map<std::string, std::string> cache;
    if (path.empty()) {
        return "unknown";
    }
    const auto cached = cache.find(path);
    if (cached != cache.end()) {
        return cached->second;
    }
    cache[path] = "not-checked";
    return cache[path];
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

