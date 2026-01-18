#define NOMINMAX
#include <windows.h>
#include <psapi.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

extern "C" __declspec(dllimport) LONG __stdcall NtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

static const ULONG SystemExtendedHandleInformation = 64;
static const LONG STATUS_INFO_LENGTH_MISMATCH = static_cast<LONG>(0xC0000004);

struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
};

struct SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
};

static std::wstring ToLower(std::wstring s)
{
    for (auto& ch : s)
    {
        ch = static_cast<wchar_t>(towlower(ch));
    }
    return s;
}

static bool StartsWithI(const std::wstring& text, const std::wstring& prefix)
{
    if (prefix.size() > text.size())
    {
        return false;
    }
    for (size_t i = 0; i < prefix.size(); i++)
    {
        if (towlower(text[i]) != towlower(prefix[i]))
        {
            return false;
        }
    }
    return true;
}

static bool EqualsI(const std::wstring& a, const std::wstring& b)
{
    if (a.size() != b.size())
    {
        return false;
    }
    for (size_t i = 0; i < a.size(); i++)
    {
        if (towlower(a[i]) != towlower(b[i]))
        {
            return false;
        }
    }
    return true;
}

static std::wstring StripDevicePrefix(const std::wstring& path)
{
    if (StartsWithI(path, L"\\\\?\\"))
    {
        return path.substr(4);
    }
    return path;
}

static std::wstring GetFullPath(const std::wstring& input)
{
    DWORD needed = GetFullPathNameW(input.c_str(), 0, nullptr, nullptr);
    if (needed == 0)
    {
        return input;
    }
    std::wstring buf;
    buf.resize(needed);
    DWORD written = GetFullPathNameW(input.c_str(), needed, &buf[0], nullptr);
    if (written == 0)
    {
        return input;
    }
    buf.resize(written);
    return buf;
}

static bool IsDirectoryPath(const std::wstring& fullPath)
{
    DWORD attrs = GetFileAttributesW(fullPath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES)
    {
        return false;
    }
    return (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

static std::wstring CanonicalizeTarget(const std::wstring& input, bool& isDir)
{
    auto p = GetFullPath(input);
    isDir = IsDirectoryPath(p);
    if (isDir)
    {
        if (!p.empty() && p.back() != L'\\')
        {
            p.push_back(L'\\');
        }
    }
    return p;
}

static std::wstring GetFinalPath(HANDLE hFile)
{
    DWORD size = GetFinalPathNameByHandleW(hFile, nullptr, 0, 0);
    if (size == 0)
    {
        return L"";
    }
    std::wstring buf;
    buf.resize(size);
    DWORD written = GetFinalPathNameByHandleW(hFile, &buf[0], size, 0);
    if (written == 0)
    {
        return L"";
    }
    buf.resize(written);
    return StripDevicePrefix(buf);
}

static std::wstring QueryProcessImagePath(HANDLE hProcess)
{
    std::wstring buf;
    buf.resize(1024);
    DWORD size = static_cast<DWORD>(buf.size());
    if (!QueryFullProcessImageNameW(hProcess, 0, &buf[0], &size))
    {
        return L"";
    }
    buf.resize(size);
    return buf;
}

static std::wstring QueryProcessUser(HANDLE hProcess)
{
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        return L"";
    }
    std::unique_ptr<void, decltype(&CloseHandle)> tokenCloser(hToken, &CloseHandle);

    DWORD needed = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &needed);
    if (needed == 0)
    {
        return L"";
    }
    std::vector<BYTE> buffer(needed);
    if (!GetTokenInformation(hToken, TokenUser, buffer.data(), needed, &needed))
    {
        return L"";
    }

    const TOKEN_USER* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
    wchar_t name[256];
    wchar_t domain[256];
    DWORD nameLen = 256;
    DWORD domainLen = 256;
    SID_NAME_USE use;
    if (!LookupAccountSidW(nullptr, user->User.Sid, name, &nameLen, domain, &domainLen, &use))
    {
        return L"";
    }

    std::wstring result;
    result.reserve(domainLen + 1 + nameLen);
    result.append(domain, domainLen);
    result.push_back(L'\\');
    result.append(name, nameLen);
    return result;
}

struct ProcessInfo
{
    DWORD pid = 0;
    std::wstring imagePath;
    std::wstring user;
    std::vector<std::wstring> lockedPaths;
};

static void PrintUsage()
{
    std::wcout << L"Usage:" << std::endl;
    std::wcout << L"  CocoUnlock.exe <file_or_folder_path> [--list|-l] [--yes|-y]" << std::endl;
    std::wcout << std::endl;
    std::wcout << L"Options:" << std::endl;
    std::wcout << L"  --list, -l   List locking processes only" << std::endl;
    std::wcout << L"  --yes, -y    Kill without confirmation" << std::endl;
}

static bool ConfirmKill(size_t processCount)
{
    std::wcout << std::endl;
    std::wcout << L"About to kill " << processCount << L" processes to unlock." << std::endl;
    std::wcout << L"Continue? (y/N): ";
    std::wstring input;
    if (!std::getline(std::wcin, input))
    {
        return false;
    }
    input = ToLower(input);
    input.erase(0, input.find_first_not_of(L" \t\r\n"));
    input.erase(input.find_last_not_of(L" \t\r\n") + 1);
    return input == L"y" || input == L"yes";
}

static void PrintProcesses(const std::vector<ProcessInfo>& processes)
{
    for (const auto& p : processes)
    {
        std::wstring name = p.imagePath.empty() ? L"" : p.imagePath.substr(p.imagePath.find_last_of(L"\\/") + 1);
        std::wcout << L"Pid=" << p.pid
                   << L" Name=" << (name.empty() ? L"<unknown>" : name)
                   << L" User=" << (p.user.empty() ? L"<unknown>" : p.user)
                   << std::endl;
        if (!p.imagePath.empty())
        {
            std::wcout << L"  Exe: " << p.imagePath << std::endl;
        }
        for (const auto& lp : p.lockedPaths)
        {
            std::wcout << L"  Locks: " << lp << std::endl;
        }
    }
}

static bool AddLockedPath(ProcessInfo& p, const std::wstring& path)
{
    for (const auto& existing : p.lockedPaths)
    {
        if (EqualsI(existing, path))
        {
            return false;
        }
    }
    p.lockedPaths.push_back(path);
    return true;
}

static void ScanModulesForMatches(HANDLE hProcess, const std::wstring& targetPath, bool targetIsDir, ProcessInfo& info)
{
    HMODULE modules[2048];
    DWORD neededBytes = 0;
    if (!EnumProcessModules(hProcess, modules, sizeof(modules), &neededBytes))
    {
        return;
    }
    const DWORD count = std::min<DWORD>(static_cast<DWORD>(neededBytes / sizeof(HMODULE)), static_cast<DWORD>(std::size(modules)));
    for (DWORD i = 0; i < count; i++)
    {
        wchar_t pathBuf[MAX_PATH];
        DWORD len = GetModuleFileNameExW(hProcess, modules[i], pathBuf, MAX_PATH);
        if (len == 0)
        {
            continue;
        }
        std::wstring modulePath(pathBuf, len);
        modulePath = GetFullPath(modulePath);

        bool match = false;
        if (targetIsDir)
        {
            match = StartsWithI(modulePath, targetPath) || EqualsI(modulePath, targetPath.substr(0, targetPath.size() - 1));
        }
        else
        {
            match = EqualsI(modulePath, targetPath);
        }

        if (match)
        {
            AddLockedPath(info, modulePath);
        }
    }
}

static std::vector<ProcessInfo> FindLockingProcesses(const std::wstring& targetPath, bool targetIsDir)
{
    ULONG returnLength = 0;
    std::vector<BYTE> buffer(32 * 1024 * 1024);
    for (;;)
    {
        LONG status = NtQuerySystemInformation(SystemExtendedHandleInformation, buffer.data(), static_cast<ULONG>(buffer.size()), &returnLength);
        if (status == 0)
        {
            break;
        }
        if (status != STATUS_INFO_LENGTH_MISMATCH)
        {
            return {};
        }
        if (returnLength == 0)
        {
            buffer.resize(buffer.size() * 2);
        }
        else
        {
            buffer.resize(static_cast<size_t>(returnLength) + 1024 * 1024);
        }
        if (buffer.size() > 1024ull * 1024ull * 1024ull)
        {
            return {};
        }
    }

    const auto* info = reinterpret_cast<const SYSTEM_HANDLE_INFORMATION_EX*>(buffer.data());
    const size_t count = static_cast<size_t>(info->NumberOfHandles);

    std::unordered_map<DWORD, ProcessInfo> processes;
    processes.reserve(512);

    std::unordered_map<DWORD, HANDLE> openProcesses;
    openProcesses.reserve(512);

    HANDLE currentProcess = GetCurrentProcess();

    for (size_t i = 0; i < count; i++)
    {
        const auto& h = info->Handles[i];
        DWORD pid = static_cast<DWORD>(h.UniqueProcessId);
        if (pid == 0)
        {
            continue;
        }

        HANDLE hProcess = nullptr;
        auto procIt = openProcesses.find(pid);
        if (procIt == openProcesses.end())
        {
            hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!hProcess)
            {
                continue;
            }
            openProcesses.emplace(pid, hProcess);
        }
        else
        {
            hProcess = procIt->second;
            if (!hProcess)
            {
                continue;
            }
        }

        HANDLE dup = nullptr;
        if (!DuplicateHandle(hProcess, reinterpret_cast<HANDLE>(h.HandleValue), currentProcess, &dup, 0, FALSE, DUPLICATE_SAME_ACCESS))
        {
            continue;
        }
        std::unique_ptr<void, decltype(&CloseHandle)> dupCloser(dup, &CloseHandle);

        if (GetFileType(dup) != FILE_TYPE_DISK)
        {
            continue;
        }

        auto finalPath = GetFinalPath(dup);
        if (finalPath.empty())
        {
            continue;
        }

        finalPath = GetFullPath(finalPath);

        bool match = false;
        if (targetIsDir)
        {
            match = StartsWithI(finalPath, targetPath) || EqualsI(finalPath, targetPath.substr(0, targetPath.size() - 1));
        }
        else
        {
            match = EqualsI(finalPath, targetPath);
        }

        if (!match)
        {
            continue;
        }

        auto it = processes.find(pid);
        if (it == processes.end())
        {
            ProcessInfo pi;
            pi.pid = pid;
            pi.imagePath = QueryProcessImagePath(hProcess);
            pi.user = QueryProcessUser(hProcess);
            it = processes.emplace(pid, std::move(pi)).first;
        }
        AddLockedPath(it->second, finalPath);
    }

    for (auto& kv : openProcesses)
    {
        if (kv.second)
        {
            CloseHandle(kv.second);
        }
    }

    std::vector<ProcessInfo> result;
    result.reserve(processes.size());
    for (auto& kv : processes)
    {
        result.push_back(std::move(kv.second));
    }

    for (auto& p : result)
    {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, p.pid);
        if (!hProcess)
        {
            continue;
        }
        std::unique_ptr<void, decltype(&CloseHandle)> closer(hProcess, &CloseHandle);
        ScanModulesForMatches(hProcess, targetPath, targetIsDir, p);
    }

    std::sort(result.begin(), result.end(), [](const ProcessInfo& a, const ProcessInfo& b)
    {
        if (a.pid != b.pid)
        {
            return a.pid < b.pid;
        }
        return a.imagePath < b.imagePath;
    });

    return result;
}

static bool KillProcess(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess)
    {
        return false;
    }
    std::unique_ptr<void, decltype(&CloseHandle)> closer(hProcess, &CloseHandle);

    if (!TerminateProcess(hProcess, 1))
    {
        return false;
    }

    DWORD waitRes = WaitForSingleObject(hProcess, 3000);
    return waitRes == WAIT_OBJECT_0;
}

int wmain(int argc, wchar_t** argv)
{
    std::ios::sync_with_stdio(false);
    std::wcin.tie(nullptr);

    bool listOnly = false;
    bool assumeYes = false;
    std::wstring targetInput;

    for (int i = 1; i < argc; i++)
    {
        std::wstring a = argv[i];
        if (a == L"-h" || a == L"--help" || a == L"/?")
        {
            PrintUsage();
            return 0;
        }
        if (a == L"-l" || a == L"--list")
        {
            listOnly = true;
            continue;
        }
        if (a == L"-y" || a == L"--yes")
        {
            assumeYes = true;
            continue;
        }
        if (!a.empty() && (a[0] == L'-' || a[0] == L'/'))
        {
            std::wcerr << L"Unknown option: " << a << std::endl;
            PrintUsage();
            return 1;
        }
        if (!targetInput.empty())
        {
            std::wcerr << L"Only one target path is allowed." << std::endl;
            PrintUsage();
            return 1;
        }
        targetInput = a;
    }

    if (targetInput.empty())
    {
        PrintUsage();
        return 1;
    }

    bool targetIsDir = false;
    std::wstring targetPath = CanonicalizeTarget(targetInput, targetIsDir);
    if (GetFileAttributesW(targetPath.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        std::wcerr << L"Path does not exist: " << targetInput << std::endl;
        return 1;
    }

    auto processes = FindLockingProcesses(targetPath, targetIsDir);
    if (processes.empty())
    {
        std::wcout << L"No locking processes found." << std::endl;
        return 0;
    }

    PrintProcesses(processes);

    if (listOnly)
    {
        return 0;
    }

    if (!assumeYes && !ConfirmKill(processes.size()))
    {
        std::wcout << L"Cancelled." << std::endl;
        return 3;
    }

    bool anyFailed = false;
    for (const auto& p : processes)
    {
        std::wcout << L"Killing: Pid=" << p.pid << std::endl;
        if (!KillProcess(p.pid))
        {
            anyFailed = true;
            std::wcerr << L"Kill failed: Pid=" << p.pid << std::endl;
        }
    }

    auto remaining = FindLockingProcesses(targetPath, targetIsDir);
    if (remaining.empty())
    {
        std::wcout << L"Unlocked." << std::endl;
        return anyFailed ? 1 : 0;
    }

    std::wcerr << L"Still locked by:" << std::endl;
    PrintProcesses(remaining);
    return 2;
}
