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
                info.hash = FastFileFingerprint(info.path.value);
                info.signer = SigningCheckStateForPath(info.path.value);
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
            result.push_back({ "driver", name[0] ? name : "<unknown>", driverPath, 0, SigningCheckStateForPath(driverPath), FastFileFingerprint(driverPath) });
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
                result.push_back({ "registry", std::string(rootName) + "\\" + path + "\\" + valueName, detail, 0, "unknown", FastFileFingerprint(detail) });
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
        info.hash = FastFileFingerprint(info.path.value);
        info.signer = SigningCheckStateForPath(info.path.value);
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
            result.push_back({ "startup", name, targetPath, 0, SigningCheckStateForPath(targetPath), FastFileFingerprint(targetPath) });
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
                result.push_back({ "startup", name, path, 0, SigningCheckStateForPath(path), FastFileFingerprint(path) });
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

