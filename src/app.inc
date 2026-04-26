class App {
public:
    int run(int argc, char* argv[]) {
        ConsoleWindow::enableVirtualTerminal();

        if (!parseArgs(argc, argv)) {
            return parseExitCode_;
        }
        loadRulesIfConfigured();
        startApiIfConfigured();

        if (options_.once) {
            InvalidateTerminalCache();
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

        InvalidateTerminalCache();
        std::cout << "\x1b[?1049h\x1b[2J\x1b[H";
        ConsoleSize lastSize = ConsoleWindow::size();
        bool running = true;
        while (running) {
            const ConsoleSize currentSize = ConsoleWindow::size();
            if (currentSize != lastSize) {
                InvalidateTerminalCache();
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

        InvalidateTerminalCache();
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

    static bool isSortValue(std::string value) {
        value = ToLower(value);
        return value == "cpu" || value == "mem" || value == "memory" || value == "pid" || value == "name";
    }

    static bool isViewValue(std::string value) {
        value = ToLower(value);
        return value == "table" || value == "tree" || value == "kernel";
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
        auto fail = [&](const std::string& message) {
            std::cerr << AppName << ": " << message << "\n\n";
            renderHelpText();
            parseExitCode_ = 2;
            return false;
        };

        auto readValue = [&](int& index, const std::string& arg, std::string& value) {
            if (index + 1 >= argc) {
                return fail("missing value for " + arg);
            }
            value = argv[++index];
            return true;
        };

        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--help" || arg == "-h" || arg == "/?") {
                renderHelpText();
                parseExitCode_ = 0;
                return false;
            }
            if (arg == "--once" || arg == "-1") {
                options_.once = true;
            } else if (arg == "--filter" || arg == "-f") {
                std::string value;
                if (!readValue(i, arg, value)) return false;
                options_.filter = value;
            } else if (arg == "--sort") {
                std::string value;
                if (!readValue(i, arg, value)) return false;
                if (!isSortValue(value)) return fail("invalid sort value: " + value);
                options_.sortMode = parseSort(value);
            } else if (arg == "--view") {
                std::string value;
                if (!readValue(i, arg, value)) return false;
                if (!isViewValue(value)) return fail("invalid view value: " + value);
                options_.viewMode = parseView(value);
            } else if (arg == "--pid" || arg == "--subtree") {
                std::string value;
                if (!readValue(i, arg, value)) return false;
                options_.subtreePid = parsePid(value);
                options_.viewMode = ViewMode::Tree;
            } else if (arg == "--hunt-pid") {
                std::string value;
                if (!readValue(i, arg, value)) return false;
                ui_.hunt.active = true;
                ui_.hunt.pid = parsePid(value);
            } else if (arg == "--refresh") {
                std::string value;
                if (!readValue(i, arg, value)) return false;
                options_.refreshMs = std::max(50, parseInt(value, options_.refreshMs));
            } else if (arg == "--limit") {
                std::string value;
                if (!readValue(i, arg, value)) return false;
                options_.rowLimit = std::max(0, parseInt(value, options_.rowLimit));
            } else if (arg == "--export-json") {
                std::string value;
                if (!readValue(i, arg, value)) return false;
                options_.exportPath = value;
                options_.once = true;
            } else if (arg == "--rules") {
                std::string value;
                if (!readValue(i, arg, value)) return false;
                options_.rulesPath = value;
            } else if (arg == "--siem-events") {
                std::string value;
                if (!readValue(i, arg, value)) return false;
                options_.siemEventsPath = value;
            } else if (arg == "--prometheus-file") {
                std::string value;
                if (!readValue(i, arg, value)) return false;
                options_.prometheusPath = value;
            } else if (arg == "--http-api") {
                options_.httpApi = true;
            } else if (arg == "--http-bind") {
                std::string value;
                if (!readValue(i, arg, value)) return false;
                options_.httpBind = value;
                options_.httpApi = true;
            } else if (arg == "--http-port") {
                std::string value;
                if (!readValue(i, arg, value)) return false;
                options_.httpPort = std::max(1, std::min(65535, parseInt(value, options_.httpPort)));
                options_.httpApi = true;
            } else if (arg == "--include-kernel") {
                options_.includeKernel = true;
            } else if (arg == "--no-kernel") {
                options_.includeKernel = false;
            } else {
                return fail("unknown option: " + arg);
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
    int parseExitCode_ = 0;
};

