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

std::string*& ActiveRenderBuffer() {
    static thread_local std::string* buffer = nullptr;
    return buffer;
}

void WriteTerminal(const std::string& text) {
    if (ActiveRenderBuffer()) {
        ActiveRenderBuffer()->append(text);
        return;
    }
    std::cout << text;
}

std::unordered_map<std::string, std::string>& TerminalLineCache() {
    static std::unordered_map<std::string, std::string> cache;
    return cache;
}

void InvalidateTerminalCache() {
    TerminalLineCache().clear();
}

class TerminalFrame {
public:
    TerminalFrame() : previous_(ActiveRenderBuffer()) {
        ActiveRenderBuffer() = &buffer_;
    }

    ~TerminalFrame() {
        flush();
        ActiveRenderBuffer() = previous_;
    }

    void flush() {
        if (flushed_) {
            return;
        }
        std::cout << buffer_;
        flushed_ = true;
    }

private:
    std::string buffer_;
    std::string* previous_ = nullptr;
    bool flushed_ = false;
};

class Renderer {
public:
    void render(const ProcessSnapshot& snapshot, const AppOptions& options, UiState& ui) const {
        TerminalFrame frame;
        const Layout layout = makeLayout(ConsoleWindow::size(), options);
        if (ui.showHelp) {
            renderHelpScreen(layout.width, layout.height);
            frame.flush();
            std::cout.flush();
            return;
        }
        if (layout.tooSmall) {
            renderTooSmall(layout);
            frame.flush();
            std::cout.flush();
            return;
        }

        if (ui.activeTab != AppTab::Processes) {
            renderSystemTab(snapshot, options, ui, layout);
            frame.flush();
            std::cout.flush();
            return;
        }

        normalizeRightPaneMode(ui);
        const auto byPid = indexByPid(snapshot.processes);
        auto rows = buildRows(snapshot.processes, options, ui);
        ensureBrowseOrderPinned(ui, rows, options);
        if (!layout.twoPane && ui.focusPane == FocusPane::GroupMembers) {
            ui.focusPane = FocusPane::ProcessList;
        }

        stabilizeSelection(ui, rows, layout.visibleRows);
        if (ui.selectionActive) {
            if (ui.rightPaneMode == RightPaneMode::Services) {
                const auto entries = rightSystemEntriesForActions(snapshot, options, ui.rightPaneMode, ui.selectedPid);
                clampRightList(ui, static_cast<int>(entries.size()), std::max(0, layout.height - 19));
            } else {
                const auto rightItems = rightPaneItemsForActions(snapshot.processes, options, ui);
                clampRightList(ui, static_cast<int>(rightItems.size()), std::max(0, layout.height - 22));
            }
        }

        const ProcessInfo* selected = findSelectedProcess(byPid, ui);

        WriteTerminal("\x1b[?25l\x1b[H");
        renderHeader(layout.width, options, ui);
        printBoxLine(3, 1, layout.width, "");
        renderLeftPane(layout.leftWidth, layout.visibleRows, rows, byPid, ui);
        if (layout.twoPane) {
            renderDivider(layout.leftWidth, layout.height);
            renderRightPane(layout.rightCol, layout.rightWidth, layout.height, snapshot, options, selected, ui);
        } else if (layout.height > 2) {
            printBoxLine(layout.height - 1, 1, layout.width, "");
        }
        renderStatusBar(layout.height, layout.width, snapshot, rows, options, ui);
        frame.flush();
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

    static std::vector<SystemEntry> rightSystemEntriesForActions(const ProcessSnapshot& snapshot, const AppOptions& options, RightPaneMode mode, DWORD selectedPid = 0) {
        if (mode == RightPaneMode::Services) {
            if (selectedPid == 0) {
                return {};
            }
            std::vector<SystemEntry> services;
            for (const auto& service : snapshot.services) {
                if (service.pid == selectedPid) {
                    services.push_back(service);
                }
            }
            return FilterSystemEntries(services, options);
        }
        return {};
    }

    int maxRows(const AppOptions& options) const {
        return makeLayout(ConsoleWindow::size(), options).visibleRows;
    }

private:
    static bool isContextualRightPaneMode(RightPaneMode mode) {
        return mode == RightPaneMode::Members ||
            mode == RightPaneMode::Details ||
            mode == RightPaneMode::Children ||
            mode == RightPaneMode::Services;
    }

    static void normalizeRightPaneMode(UiState& ui) {
        if (isContextualRightPaneMode(ui.rightPaneMode)) {
            return;
        }
        ui.rightPaneMode = RightPaneMode::Details;
        ui.rightSelectedIndex = 0;
        ui.rightScroll = 0;
        ui.rightPathScroll = 0;
    }

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

    static std::string scrollingText(const std::string& value, int width, int offset) {
        if (width <= 0) {
            return {};
        }
        const int safeOffset = std::max(0, offset);
        std::string visible = SliceTo(value, static_cast<std::size_t>(safeOffset), static_cast<std::size_t>(width));
        const bool hasMoreLeft = safeOffset > 0;
        const bool hasMoreRight = value.size() > static_cast<std::size_t>(safeOffset + width);
        if (!visible.empty() && hasMoreLeft) {
            visible[0] = '<';
        }
        if (!visible.empty() && hasMoreRight) {
            visible[visible.size() - 1] = '>';
        }
        return visible;
    }

    static std::string scrollingLine(const std::string& value, int width, int offset) {
        return fitLine(scrollingText(value, width, offset), width);
    }

    static std::string scrollingTail(const std::string& prefix, const std::string& value, int width, int offset) {
        const int tailWidth = width - static_cast<int>(prefix.size());
        if (tailWidth <= 4) {
            return scrollingLine(prefix + value, width, offset);
        }
        return fitLine(prefix + scrollingText(value, tailWidth, offset), width);
    }

    static std::string scrollingField(const std::string& label, const std::string& value, int width, int offset) {
        const std::string prefix = label + " ";
        const int valueWidth = std::max(1, width - static_cast<int>(prefix.size()));
        std::string visible = scrollingText(value, valueWidth, offset);
        return fitLine(prefix + visible, width);
    }

    struct StyledLine {
        std::string text;
        const char* color = Ansi::Reset;
    };

    static void setStyledLine(std::vector<StyledLine>& lines, int firstRow, int row, std::string text, const char* color = Ansi::Reset) {
        const int index = row - firstRow;
        if (index < 0 || index >= static_cast<int>(lines.size())) {
            return;
        }
        lines[static_cast<std::size_t>(index)] = { std::move(text), color };
    }

    static void flushStyledPane(int col, int width, int firstRow, const std::vector<StyledLine>& lines) {
        for (int i = 0; i < static_cast<int>(lines.size()); ++i) {
            const auto& line = lines[static_cast<std::size_t>(i)];
            printBoxLine(firstRow + i, col, width, line.text, line.color);
        }
    }

    static void printAt(int row, int col, const std::string& text) {
        if (row <= 0 || col <= 0) {
            return;
        }
        const std::string key = std::to_string(row) + ":" + std::to_string(col);
        auto& cache = TerminalLineCache();
        const auto cached = cache.find(key);
        if (cached != cache.end() && cached->second == text) {
            return;
        }
        cache[key] = text;
        WriteTerminal("\x1b[" + std::to_string(row) + ";" + std::to_string(col) + "H" + text);
    }

    static void printBoxLine(int row, int col, int width, const std::string& text, const char* color = Ansi::Reset) {
        if (width <= 0) {
            return;
        }
        printAt(row, col, std::string(color) + fitLine(text, width) + Ansi::Reset);
    }

    static void renderTooSmall(const Layout& layout) {
        WriteTerminal("\x1b[?25l\x1b[H");
        for (int row = 1; row <= layout.height; ++row) {
            printBoxLine(row, 1, layout.width, "");
        }
        printBoxLine(1, 1, layout.width, AppName, Ansi::Cyan);
        printBoxLine(3, 1, layout.width, "Window is too small", Ansi::Orange);
        printBoxLine(4, 1, layout.width, "Resize to at least 52x12", Ansi::Dim);
        printBoxLine(6, 1, layout.width, "q quit | F1 help", Ansi::Dim);
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
            ? (ui.activeTab == AppTab::Processes
                ? "1 proc | 2 " + StartupAreaName() + " | 3 drivers | / filter | F1 help | PgUp/PgDn | Tab pane | q quit"
                : "1 proc | 2 " + StartupAreaName() + " | 3 drivers | / filter | Enter select | d clear | q quit")
            : (ui.activeTab == AppTab::Processes
                ? "1 proc | 2 " + StartupAreaName() + " | 3 drivers | / filter | F1 help | PgUp/PgDn | q quit"
                : "1 proc | 2 " + StartupAreaName() + " | 3 drivers | / filter | Enter select | q quit");
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
               << std::setw(7) << "SYSCPU"
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

        WriteTerminal("\x1b[?25l\x1b[H");
        renderHeader(layout.width, options, ui);
        printBoxLine(3, 1, layout.width, "");
        const std::string title = ui.activeTab == AppTab::Registry ? StartupAreaTitle() : "KERNEL DRIVERS";
        printBoxLine(4, 1, layout.width, title, Ansi::Cyan);
        printBoxLine(5, 1, layout.width, ui.activeTab == AppTab::Registry ? StartupAreaColumnTitle() : "DRIVER / PATH", Ansi::Dim);

        if (entries.empty()) {
            printBoxLine(7, 3, layout.width - 4, options.filter.empty() ? "No entries visible or access denied." : "No entries match the filter.", Ansi::Orange);
        }

        const int bodyLastRow = std::max(5, layout.height - 1);
        for (int row = 6; row <= bodyLastRow; ++row) {
            const int visibleOffset = row - 6;
            if (visibleOffset >= layout.visibleRows) {
                printBoxLine(row, 1, layout.width, "");
                continue;
            }
            const int index = ui.scroll + visibleOffset;
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
               << " | Enter select row | d clear"
               << " | 1 processes | 2 " << StartupAreaName() << " | 3 drivers | / filter | " << (ui.message.text.empty() ? "ready" : ui.message.text);
        printBoxLine(layout.height, 1, layout.width, status.str(), ui.message.ttlFrames > 0 ? notificationColor(ui.message.kind) : Ansi::Dim);
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
        const int firstRow = 4;
        const int lastRow = std::max(firstRow, height - 1);
        const int footerStart = std::max(16, height - 4);
        std::vector<StyledLine> pane(static_cast<std::size_t>(lastRow - firstRow + 1));
        auto put = [&](int row, std::string text, const char* color = Ansi::Reset) {
            setStyledLine(pane, firstRow, row, std::move(text), color);
        };

        put(4, "SELECTED PROCESS", Ansi::Cyan);
        if (selected) {
            put(5, field("pid", std::to_string(selected->pid), width));
            put(6, field("name", selected->name, width));
            put(7, field("sid", selected->sid.ok() ? selected->sid.value : selected->sid.status, width));
            put(8, field("svc", selected->service.empty() ? "<none>" : selected->service, width));
            put(9, field("path", selected->path.ok() ? selected->path.value : selected->path.status, width));
            put(10, field("syscpu/mem", std::to_string(static_cast<int>(selected->cpu)) + "% / " + MemoryMb(selected->workingSet) + " MB", width));
        } else {
            put(5, "<nothing selected>", Ansi::Dim);
        }

        put(12, "RIGHT PANE [" + RightPaneModeName(ui.rightPaneMode) + "]  [ ] switch", Ansi::Cyan);

        if (ui.rightPaneMode == RightPaneMode::Services) {
            const std::vector<SystemEntry> entries = rightSystemEntriesForActions(snapshot, options, ui.rightPaneMode, selected ? selected->pid : 0);
            renderSystemEntries(pane, firstRow, width, footerStart, entries, ui);
            flushStyledPane(col, width, firstRow, pane);
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
                put(13, "pid      " + std::to_string(selected->pid), Ansi::Orange);
                put(14, "ppid     " + std::to_string(selected->parentPid));
                put(15, "threads  " + std::to_string(selected->threads));
                put(16, "children " + std::to_string(childCount));
                put(17, "memory   " + MemoryMb(selected->workingSet) + " MB");
                put(18, "syscpu   " + std::to_string(static_cast<int>(selected->cpu)) + "%");
                put(19, "service  " + (selected->service.empty() ? "<none>" : selected->service));
                put(20, "signer   " + selected->signer);
                put(21, "hash     " + selected->hash);
                put(22, scrollingField("cmd     ", selected->commandLine, width, ui.rightPathScroll));
                put(23, scrollingField("path    ", selected->path.display(), width, ui.rightPathScroll));
                if (ui.hunt.active && ui.hunt.pid == selected->pid) {
                    std::ostringstream huntLine;
                    huntLine << "hunt syscpu " << std::fixed << std::setprecision(1) << ui.hunt.lastCpu
                             << "% peak " << ui.hunt.peakCpu
                             << "% mem " << MemoryMb(ui.hunt.lastWorkingSet)
                             << "/" << MemoryMb(ui.hunt.peakWorkingSet) << " MB";
                    put(24, huntLine.str(), ui.hunt.alert.empty() ? Ansi::Green : Ansi::Red);
                    put(25, "alert    " + (ui.hunt.alert.empty() ? std::string("none") : ui.hunt.alert), ui.hunt.alert.empty() ? Ansi::Dim : Ansi::Red);
                }
            } else {
                put(13, "No process selected", Ansi::Orange);
                put(14, "Enter selects a row");
                put(15, "d or Esc clears selection");
            }
        } else if (selected && ui.rightPaneMode == RightPaneMode::Members && !items.empty()) {
            std::ostringstream summary;
            summary << selectedGroup.count << "x " << selectedGroup.name
                    << " | syscpu " << std::fixed << std::setprecision(1) << selectedGroup.cpu
                    << " | mem " << MemoryMb(selectedGroup.workingSet) << " MB";
            put(14, summary.str(), Ansi::Orange);
        } else if (selected && ui.rightPaneMode == RightPaneMode::Children && !items.empty()) {
            put(14, std::to_string(items.size()) + " child process(es)", Ansi::Orange);
        } else if (ui.rightPaneMode != RightPaneMode::Details) {
            put(14, selected ? "No visible " + RightPaneModeName(ui.rightPaneMode) : "No process selected", Ansi::Orange);
            put(15, selected ? "Filter may be hiding items" : "Select a process first", Ansi::Dim);
            put(16, selected ? "Try another mode with [ or ]" : "Enter selects the focused row", Ansi::Dim);
        }

        if (ui.rightPaneMode != RightPaneMode::Details) {
            put(13, "pid    scpu memMB    service/name");
            const int maxMembers = std::max(0, footerStart - 16);
            for (int i = 0; i < maxMembers; ++i) {
                const int rowNo = 16 + i;
                const int index = ui.rightScroll + i;
                if (index >= static_cast<int>(items.size())) {
                    continue;
                }

                const auto& item = items[static_cast<std::size_t>(index)];
                std::ostringstream row;
                row << std::left
                    << std::setw(7) << item.pid
                    << std::setw(5) << static_cast<int>(item.cpu)
                    << std::setw(9) << MemoryMb(item.workingSet);
                const std::string prefix = row.str();
                const std::string tail = item.service.empty() ? item.name : item.service;

                const bool isRightCursor = ui.focusPane == FocusPane::GroupMembers && index == ui.rightSelectedIndex;
                const bool isSelectedMember = selected && item.pid == selected->pid;
                const bool isHuntedMember = ui.hunt.active && item.pid == ui.hunt.pid;
                put(rowNo, scrollingTail(prefix, tail, width, ui.rightPathScroll), isRightCursor ? (isSelectedMember ? Ansi::OrangeBg : Ansi::FocusBg) : (isSelectedMember ? Ansi::Orange : (isHuntedMember ? Ansi::Green : Ansi::Reset)));
            }
        }

        put(footerStart, "MODE HINTS", Ansi::Cyan);
        put(footerStart + 1, modeHints(options, ui), Ansi::Dim);
        if (ui.hunt.active) {
            const char* huntColor = ui.hunt.alert.empty() ? Ansi::Green : Ansi::Red;
            const std::string state = ui.hunt.alert.empty() ? ui.hunt.status : ui.hunt.alert;
            put(footerStart + 2, "hunt " + std::to_string(ui.hunt.pid) + " " + ui.hunt.name + ": " + state, huntColor);
        } else {
            put(footerStart + 2, "hunt: inactive", Ansi::Dim);
        }
        put(footerStart + 3, focusHint(ui), Ansi::Dim);
        flushStyledPane(col, width, firstRow, pane);
    }

    static void renderSystemEntries(std::vector<StyledLine>& pane, int firstRow, int width, int footerStart, const std::vector<SystemEntry>& entries, const UiState& ui) {
        auto put = [&](int row, std::string text, const char* color = Ansi::Reset) {
            setStyledLine(pane, firstRow, row, std::move(text), color);
        };
        const RightPaneMode mode = ui.rightPaneMode;
        std::string heading;
        if (mode == RightPaneMode::Services) {
            heading = "service        pid      state";
        } else if (mode == RightPaneMode::Drivers) {
            heading = "kernel driver  path";
        } else {
            heading = StartupAreaColumnTitle();
        }

        put(13, heading, Ansi::Dim);
        if (entries.empty()) {
            put(15, mode == RightPaneMode::Services ? "no services bound to selected PID" : "no filtered entries", Ansi::Orange);
        }
        const int maxRows = std::max(0, footerStart - 15);
        for (int i = 0; i < maxRows; ++i) {
            const int row = 15 + i;
            const int index = ui.rightScroll + i;
            if (index >= static_cast<int>(entries.size())) {
                continue;
            }
            const auto& entry = entries[static_cast<std::size_t>(index)];
            std::string line;
            if (mode == RightPaneMode::Services) {
                std::ostringstream row;
                row << std::left << std::setw(15) << TrimTo(entry.name, 14)
                    << std::setw(9) << entry.pid
                    << entry.detail;
                line = scrollingLine(row.str(), width, ui.rightPathScroll);
            } else if (mode == RightPaneMode::Drivers) {
                const std::string name = TrimTo(entry.name, 17);
                const std::string signer = TrimTo(entry.signer, 11);
                std::ostringstream prefix;
                prefix << std::left << std::setw(18) << name
                       << std::setw(12) << signer;
                line = scrollingTail(prefix.str(), entry.detail, width, ui.rightPathScroll);
            } else {
                const std::string fullLine = entry.name + "  " + entry.detail;
                line = scrollingLine(fullLine, width, ui.rightPathScroll);
            }
            const bool cursor = ui.focusPane == FocusPane::GroupMembers && index == ui.rightSelectedIndex;
            put(row, line, cursor ? Ansi::FocusBg : (mode == RightPaneMode::Drivers ? Ansi::Orange : Ansi::Reset));
        }

        put(footerStart, "TRACE SUMMARY", Ansi::Cyan);
        put(footerStart + 1, std::to_string(entries.size()) + " " + RightPaneModeName(mode) + " entries", Ansi::Dim);
        put(footerStart + 2, entries.empty() ? "no filtered entries" : "Enter follows PID when available", Ansi::Dim);
        put(footerStart + 3, focusHint(ui), Ansi::Dim);
    }

    static std::string focusHint(const UiState& ui) {
        if (ui.focusPane == FocusPane::GroupMembers) {
            if (ui.rightPaneMode == RightPaneMode::Details) {
                return "details active: Left/Right scroll | [] modes | Esc back";
            }
            return "right active: Enter pick | Left/Right scroll | PgUp/PgDn | Esc";
        }
        return "left active: Enter select | Tab right | Esc deselect";
    }

    static std::string modeHints(const AppOptions& options, const UiState& ui) {
        if (ui.focusPane == FocusPane::GroupMembers) {
            if (ui.rightPaneMode == RightPaneMode::Details) {
                return "details: Left/Right scroll cmd/path | [] pane mode | Esc";
            }
            return "right: Left/Right scroll text | Enter pick | x hunt | PgUp/PgDn";
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
            printBoxLine(row, leftWidth + 1, 1, "");
            printBoxLine(row, leftWidth + 2, 1, "|", Ansi::Dim);
            printBoxLine(row, leftWidth + 3, 1, "");
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
        const int activePathScroll = ui.focusPane == FocusPane::GroupMembers ? ui.rightPathScroll : ui.pathScroll;
        status << "rows " << (rows.empty() ? 0 : ui.selectedIndex + 1) << "/" << rows.size()
               << " | pids " << snapshot.processes.size()
               << " | focus " << (ui.focusPane == FocusPane::ProcessList ? "left" : "right")
               << " | selected " << (ui.selectionActive ? std::to_string(ui.selectedPid) : std::string("none"))
               << " | path offset " << activePathScroll;
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
        WriteTerminal("\x1b[?25l\x1b[H");
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

        const int adaptiveStep = adaptiveNavigationStep(ui, command);

        switch (command) {
        case Command::Quit:
            return false;
        case Command::MoveUp:
            moveSelection(ui, snapshot, options, -adaptiveStep);
            break;
        case Command::MoveDown:
            moveSelection(ui, snapshot, options, adaptiveStep);
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
            if (ui.focusPane == FocusPane::GroupMembers) {
                ui.rightPathScroll = std::max(0, ui.rightPathScroll - adaptiveStep * 4);
            } else {
                ui.pathScroll = std::max(0, ui.pathScroll - adaptiveStep * 4);
            }
            break;
        case Command::ScrollPathRight:
            if (ui.focusPane == FocusPane::GroupMembers) {
                ui.rightPathScroll += adaptiveStep * 4;
            } else {
                ui.pathScroll += adaptiveStep * 4;
            }
            break;
        case Command::FocusNextPane:
            if (!requireProcessTab(ui, "right pane")) {
                break;
            }
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
            if (!requireProcessTab(ui, "right pane modes")) {
                break;
            }
            cycleRightPaneMode(ui, true);
            break;
        case Command::PrevRightPaneMode:
            if (!requireProcessTab(ui, "right pane modes")) {
                break;
            }
            cycleRightPaneMode(ui, false);
            break;
        case Command::HuntFocused:
            if (!requireProcessTab(ui, "hunt")) {
                break;
            }
            huntFocused(ui, snapshot, options);
            break;
        case Command::SubtreeFocused:
            if (!requireProcessTab(ui, "subtree")) {
                break;
            }
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
            ui.rightPathScroll = 0;
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
            if (!requireProcessTab(ui, "subtree")) {
                break;
            }
            promptSubtree(options, ui, snapshot);
            break;
        case Command::RequestKill:
            if (!requireProcessTab(ui, "kill")) {
                break;
            }
            requestKill(ui, snapshot);
            break;
        case Command::ConfirmYes:
            confirmKill(ui);
            break;
        case Command::ConfirmNo:
            cancelKill(ui);
            break;
        case Command::ToggleHunt:
            if (!requireProcessTab(ui, "hunt")) {
                break;
            }
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
    static int adaptiveNavigationStep(UiState& ui, Command command) {
        const bool accelerates = command == Command::MoveUp ||
            command == Command::MoveDown ||
            command == Command::ScrollPathLeft ||
            command == Command::ScrollPathRight;
        const auto now = std::chrono::steady_clock::now();
        if (!accelerates) {
            ui.repeatCommand = Command::None;
            ui.repeatCount = 0;
            ui.repeatAt = now;
            return 1;
        }

        const auto elapsed = now - ui.repeatAt;
        if (ui.repeatCommand == command && elapsed <= std::chrono::milliseconds(260)) {
            ui.repeatCount = std::min(ui.repeatCount + 1, 18);
        } else {
            ui.repeatCommand = command;
            ui.repeatCount = 0;
        }
        ui.repeatAt = now;

        if (ui.repeatCount >= 14) return 8;
        if (ui.repeatCount >= 10) return 5;
        if (ui.repeatCount >= 6) return 3;
        if (ui.repeatCount >= 3) return 2;
        return 1;
    }

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

    static bool requireProcessTab(UiState& ui, const std::string& action) {
        if (ui.activeTab == AppTab::Processes) {
            return true;
        }
        ui.notify(NotificationKind::Info, action + " works in the process tab; Enter selects " + TabName(ui.activeTab) + " rows");
        return false;
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
        ui.pathScroll = 0;
        ui.rightPathScroll = 0;
        restoreTabCursor(ui);
        ui.rightSelectedIndex = 0;
        ui.rightScroll = 0;
        InvalidateTerminalCache();
        if (tab != AppTab::Processes) {
            clearLiveSortHold(ui);
            ui.hunt = HuntState{};
        }
        ui.notify(NotificationKind::Info, "tab: " + TabName(tab));
    }

    static RightPaneMode nextRightPaneMode(RightPaneMode current, bool forward) {
        if (forward) {
            switch (current) {
            case RightPaneMode::Members: return RightPaneMode::Details;
            case RightPaneMode::Details: return RightPaneMode::Children;
            case RightPaneMode::Children: return RightPaneMode::Services;
            case RightPaneMode::Services: return RightPaneMode::Members;
            case RightPaneMode::Drivers: return RightPaneMode::Members;
            case RightPaneMode::Registry: return RightPaneMode::Members;
            }
        } else {
            switch (current) {
            case RightPaneMode::Members: return RightPaneMode::Services;
            case RightPaneMode::Details: return RightPaneMode::Members;
            case RightPaneMode::Children: return RightPaneMode::Details;
            case RightPaneMode::Services: return RightPaneMode::Children;
            case RightPaneMode::Drivers: return RightPaneMode::Services;
            case RightPaneMode::Registry: return RightPaneMode::Services;
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
        ui.rightPathScroll = 0;
    }

    void moveRightSelection(UiState& ui, const ProcessSnapshot& snapshot, const AppOptions& options, int delta) {
        if (!ui.selectionActive) {
            ui.notify(NotificationKind::Warning, "select a process before using the right pane");
            return;
        }
        if (ui.rightPaneMode == RightPaneMode::Services) {
            const auto entries = renderer_.rightSystemEntriesForActions(snapshot, options, ui.rightPaneMode, ui.selectedPid);
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
            if (ui.rightPaneMode == RightPaneMode::Services) {
                const auto entries = renderer_.rightSystemEntriesForActions(snapshot, options, ui.rightPaneMode, ui.selectedPid);
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
        ui.rightPathScroll = 0;
        ui.notify(NotificationKind::Info, "right pane: " + RightPaneModeName(ui.rightPaneMode));
    }

    DWORD focusedPid(const UiState& ui, const ProcessSnapshot& snapshot, const AppOptions& options) {
        if (ui.focusPane == FocusPane::GroupMembers && ui.rightPaneMode != RightPaneMode::Details) {
            if (ui.rightPaneMode == RightPaneMode::Services) {
                const auto entries = renderer_.rightSystemEntriesForActions(snapshot, options, ui.rightPaneMode, ui.selectedPid);
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
                ui.rightPathScroll = 0;
                return;
            }
        }
        ui.selectedPid = pid;
        ui.selectionActive = true;
        ui.rightSelectedIndex = 0;
        ui.rightScroll = 0;
        ui.rightPathScroll = 0;
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
                const bool systemMode = ui.rightPaneMode == RightPaneMode::Services;
                const bool hasItems = systemMode
                    ? !renderer_.rightSystemEntriesForActions(snapshot, options, ui.rightPaneMode, ui.selectedPid).empty()
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
            if (ui.rightPaneMode == RightPaneMode::Services) {
                const auto entries = renderer_.rightSystemEntriesForActions(snapshot, options, ui.rightPaneMode, ui.selectedPid);
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
        ui.rightPathScroll = 0;
        ui.notify(NotificationKind::Success, "selected PID " + std::to_string(ui.selectedPid));
    }

    static void deselect(UiState& ui) {
        ui.selectionActive = false;
        ui.selectedPid = 0;
        ui.rightSelectedIndex = 0;
        ui.rightScroll = 0;
        ui.rightPathScroll = 0;
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
        InvalidateTerminalCache();
        ui.scroll = 0;
        ui.rightSelectedIndex = 0;
        ui.rightScroll = 0;
        ui.rightPathScroll = 0;
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
        InvalidateTerminalCache();

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

