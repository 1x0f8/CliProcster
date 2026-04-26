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
        sendAll(client, text);
    }

    static bool sendAll(Socket client, const std::string& text) {
        std::size_t offset = 0;
        while (offset < text.size()) {
            const std::size_t remaining = text.size() - offset;
            const int chunk = static_cast<int>(std::min<std::size_t>(remaining, 16384));
            const int sent = send(client, text.data() + offset, chunk, 0);
            if (sent <= 0) {
                return false;
            }
            offset += static_cast<std::size_t>(sent);
        }
        return true;
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

