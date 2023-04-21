// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Copyright (c) 2014-2025 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/system.h>

#include <support/allocators/secure.h>

#include <ctpl_stl.h>
#include <fs.h>
#include <logging.h>
#include <stacktraces.h>
#include <util/string.h>
#include <util/syserror.h>
#include <util/threadnames.h>
#include <util/time.h>

#include <tinyformat.h>

#if (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__))
#include <pthread.h>
#include <pthread_np.h>
#endif

#ifndef WIN32
// for posix_fallocate, in configure.ac we check if it is present after this
#ifdef __linux__

#ifdef _POSIX_C_SOURCE
#undef _POSIX_C_SOURCE
#endif

#define _POSIX_C_SOURCE 200112L

#endif // __linux__

#include <atomic>
#include <sched.h>
#include <sys/stat.h>
#else
#include <codecvt>

#include <io.h> /* for _commit */
#endif

#ifdef HAVE_MALLOPT_ARENA_MAX
#include <malloc.h>
#endif

#include <cstdlib>
#include <locale>
#include <stdexcept>
#include <string>
#include <thread>

// Application startup time (used for uptime calculation)
const int64_t nStartupTime = GetTime();

//Dash only features
const std::string gCoinJoinName = "CoinJoin";

/**
    nWalletBackups:
        1..10   - number of automatic backups to keep
        0       - disabled by command-line
        -1      - disabled because of some error during run-time
        -2      - disabled because wallet was locked and we were not able to replenish keypool
*/
int nWalletBackups = 10;

/** Mutex to protect dir_locks. */
static GlobalMutex cs_dir_locks;

/** A map that contains all the currently held directory locks. After
 * successful locking, these will be held here until the global destructor
 * cleans them up and thus automatically unlocks them, or ReleaseDirectoryLocks
 * is called.
 */
static std::map<std::string, std::unique_ptr<fsbridge::FileLock>> dir_locks GUARDED_BY(cs_dir_locks);

bool LockDirectory(const fs::path& directory, const fs::path& lockfile_name, bool probe_only)
{
    LOCK(cs_dir_locks);
    fs::path pathLockFile = directory / lockfile_name;

    // If a lock for this directory already exists in the map, don't try to re-lock it
    if (dir_locks.count(fs::PathToString(pathLockFile))) {
        return true;
    }

    // Create empty lock file if it doesn't exist.
    FILE* file = fsbridge::fopen(pathLockFile, "a");
    if (file) fclose(file);
    auto lock = std::make_unique<fsbridge::FileLock>(pathLockFile);
    if (!lock->TryLock()) {
        return error("Error while attempting to lock directory %s: %s", fs::PathToString(directory), lock->GetReason());
    }
    if (!probe_only) {
        // Lock successful and we're not just probing, put it into the map
        dir_locks.emplace(fs::PathToString(pathLockFile), std::move(lock));
    }
    return true;
}

void UnlockDirectory(const fs::path& directory, const fs::path& lockfile_name)
{
    LOCK(cs_dir_locks);
    dir_locks.erase(fs::PathToString(directory / lockfile_name));
}

void ReleaseDirectoryLocks()
{
    LOCK(cs_dir_locks);
    dir_locks.clear();
}

bool DirIsWritable(const fs::path& directory)
{
    fs::path tmpFile = GetUniquePath(directory);

    FILE* file = fsbridge::fopen(tmpFile, "a");
    if (!file) return false;

    fclose(file);
    remove(tmpFile);

    return true;
}

bool CheckDiskSpace(const fs::path& dir, uint64_t additional_bytes)
{
    constexpr uint64_t min_disk_space = 52428800; // 50 MiB

    uint64_t free_bytes_available = fs::space(dir).available;
    return free_bytes_available >= min_disk_space + additional_bytes;
}

std::streampos GetFileSize(const char* path, std::streamsize max) {
    std::ifstream file{path, std::ios::binary};
    file.ignore(max);
    return file.gcount();
}

void PrintExceptionContinue(const std::exception_ptr pex, const char* pszExceptionOrigin)
{
    std::string message = strprintf("\"%s\" raised an exception\n%s", pszExceptionOrigin, GetPrettyExceptionStr(pex));
    LogPrintf("\n\n************************\n%s\n", message);
    tfm::format(std::cerr, "\n\n************************\n%s\n", message);
}

bool RenameOver(fs::path src, fs::path dest)
{
    std::error_code error;
    fs::rename(src, dest, error);
    return !error;
}

/**
 * Ignores exceptions thrown by create_directories if the requested directory exists.
 * Specifically handles case where path p exists, but it wasn't possible for the user to
 * write to the parent directory.
 */
bool TryCreateDirectories(const fs::path& p)
{
    try
    {
        return fs::create_directories(p);
    } catch (const fs::filesystem_error&) {
        if (!fs::exists(p) || !fs::is_directory(p))
            throw;
    }

    // create_directories didn't create the directory, it had to have existed already
    return false;
}

bool FileCommit(FILE *file)
{
    if (fflush(file) != 0) { // harmless if redundantly called
        LogPrintf("fflush failed: %s\n", SysErrorString(errno));
        return false;
    }
#ifdef WIN32
    HANDLE hFile = (HANDLE)_get_osfhandle(_fileno(file));
    if (FlushFileBuffers(hFile) == 0) {
        LogPrintf("FlushFileBuffers failed: %s\n", Win32ErrorString(GetLastError()));
        return false;
    }
#elif defined(MAC_OSX) && defined(F_FULLFSYNC)
    if (fcntl(fileno(file), F_FULLFSYNC, 0) == -1) { // Manpage says "value other than -1" is returned on success
        LogPrintf("fcntl F_FULLFSYNC failed: %s\n", SysErrorString(errno));
        return false;
    }
#elif HAVE_FDATASYNC
    if (fdatasync(fileno(file)) != 0 && errno != EINVAL) { // Ignore EINVAL for filesystems that don't support sync
        LogPrintf("fdatasync failed: %d\n", SysErrorString(errno));
        return false;
    }
#else
    if (fsync(fileno(file)) != 0 && errno != EINVAL) {
        LogPrintf("fsync failed: %d\n", SysErrorString(errno));
        return false;
    }
#endif
    return true;
}

void DirectoryCommit(const fs::path &dirname)
{
#ifndef WIN32
    FILE* file = fsbridge::fopen(dirname, "r");
    if (file) {
        fsync(fileno(file));
        fclose(file);
    }
#endif
}

bool TruncateFile(FILE *file, unsigned int length) {
#if defined(WIN32)
    return _chsize(_fileno(file), length) == 0;
#else
    return ftruncate(fileno(file), length) == 0;
#endif
}

/**
 * this function tries to raise the file descriptor limit to the requested number.
 * It returns the actual file descriptor limit (which may be more or less than nMinFD)
 */
int RaiseFileDescriptorLimit(int nMinFD) {
#if defined(WIN32)
    return 2048;
#else
    struct rlimit limitFD;
    if (getrlimit(RLIMIT_NOFILE, &limitFD) != -1) {
        if (limitFD.rlim_cur < (rlim_t)nMinFD) {
            limitFD.rlim_cur = nMinFD;
            if (limitFD.rlim_cur > limitFD.rlim_max)
                limitFD.rlim_cur = limitFD.rlim_max;
            setrlimit(RLIMIT_NOFILE, &limitFD);
            getrlimit(RLIMIT_NOFILE, &limitFD);
        }
        return limitFD.rlim_cur;
    }
    return nMinFD; // getrlimit failed, assume it's fine
#endif
}

/**
 * this function tries to make a particular range of a file allocated (corresponding to disk space)
 * it is advisory, and the range specified in the arguments will never contain live data
 */
void AllocateFileRange(FILE *file, unsigned int offset, unsigned int length) {
#if defined(WIN32)
    // Windows-specific version
    HANDLE hFile = (HANDLE)_get_osfhandle(_fileno(file));
    LARGE_INTEGER nFileSize;
    int64_t nEndPos = (int64_t)offset + length;
    nFileSize.u.LowPart = nEndPos & 0xFFFFFFFF;
    nFileSize.u.HighPart = nEndPos >> 32;
    SetFilePointerEx(hFile, nFileSize, 0, FILE_BEGIN);
    SetEndOfFile(hFile);
#elif defined(MAC_OSX)
    // OSX specific version
    // NOTE: Contrary to other OS versions, the OSX version assumes that
    // NOTE: offset is the size of the file.
    fstore_t fst;
    fst.fst_flags = F_ALLOCATECONTIG;
    fst.fst_posmode = F_PEOFPOSMODE;
    fst.fst_offset = 0;
    fst.fst_length = length; // mac os fst_length takes the # of free bytes to allocate, not desired file size
    fst.fst_bytesalloc = 0;
    if (fcntl(fileno(file), F_PREALLOCATE, &fst) == -1) {
        fst.fst_flags = F_ALLOCATEALL;
        fcntl(fileno(file), F_PREALLOCATE, &fst);
    }
    ftruncate(fileno(file), static_cast<off_t>(offset) + length);
#else
    #if defined(HAVE_POSIX_FALLOCATE)
    // Version using posix_fallocate
    off_t nEndPos = (off_t)offset + length;
    if (0 == posix_fallocate(fileno(file), 0, nEndPos)) return;
    #endif
    // Fallback version
    // TODO: just write one byte per block
    static const char buf[65536] = {};
    if (fseek(file, offset, SEEK_SET)) {
        return;
    }
    while (length > 0) {
        unsigned int now = 65536;
        if (length < now)
            now = length;
        fwrite(buf, 1, now, file); // allowed to fail; this function is advisory anyway
        length -= now;
    }
#endif
}

#ifdef WIN32
fs::path GetSpecialFolderPath(int nFolder, bool fCreate)
{
    WCHAR pszPath[MAX_PATH] = L"";

    if(SHGetSpecialFolderPathW(nullptr, pszPath, nFolder, fCreate))
    {
        return fs::path(pszPath);
    }

    LogPrintf("SHGetSpecialFolderPathW() failed, could not obtain requested path.\n");
    return fs::path("");
}
#endif

#ifndef WIN32
std::string ShellEscape(const std::string& arg)
{
    std::string escaped = arg;
    ReplaceAll(escaped, "'", "'\"'\"'");
    return "'" + escaped + "'";
}
#endif

#if HAVE_SYSTEM
void runCommand(const std::string& strCommand)
{
    if (strCommand.empty()) return;
#ifndef WIN32
    int nErr = ::system(strCommand.c_str());
#else
    int nErr = ::_wsystem(std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>,wchar_t>().from_bytes(strCommand).c_str());
#endif
    if (nErr)
        LogPrintf("runCommand error: system(%s) returned %d\n", strCommand, nErr);
}
#endif

void RenameThreadPool(ctpl::thread_pool& tp, const char* baseName)
{
    auto cond = std::make_shared<std::condition_variable>();
    auto mutex = std::make_shared<std::mutex>();
    std::atomic<int> doneCnt(0);
    std::map<int, std::future<void> > futures;

    for (int i = 0; i < tp.size(); i++) {
        futures[i] = tp.push([baseName, i, cond, mutex, &doneCnt](int threadId) {
            util::ThreadRename(strprintf("%s-%d", baseName, i));
            std::unique_lock<std::mutex> l(*mutex);
            doneCnt++;
            cond->wait(l);
        });
    }

    do {
        // Always sleep to let all threads acquire locks
        UninterruptibleSleep(std::chrono::milliseconds{10});
        // `doneCnt` should be at least `futures.size()` if tp size was increased (for whatever reason),
        // or at least `tp.size()` if tp size was decreased and queue was cleared
        // (which can happen on `stop()` if we were not fast enough to get all jobs to their threads).
    } while (uint64_t(doneCnt) < futures.size() && doneCnt < tp.size());

    cond->notify_all();

    // Make sure no one is left behind, just in case
    for (auto& pair : futures) {
        auto& f = pair.second;
        if (f.valid() && f.wait_for(std::chrono::milliseconds(2000)) == std::future_status::timeout) {
            LogPrintf("%s: %s-%d timed out\n", __func__, baseName, pair.first);
            // Notify everyone again
            cond->notify_all();
            break;
        }
    }
}

void SetupEnvironment()
{
#ifdef HAVE_MALLOPT_ARENA_MAX
    // glibc-specific: On 32-bit systems set the number of arenas to 1.
    // By default, since glibc 2.10, the C library will create up to two heap
    // arenas per core. This is known to cause excessive virtual address space
    // usage in our usage. Work around it by setting the maximum number of
    // arenas to 1.
    if (sizeof(void*) == 4) {
        mallopt(M_ARENA_MAX, 1);
    }
#endif
    // On most POSIX systems (e.g. Linux, but not BSD) the environment's locale
    // may be invalid, in which case the "C.UTF-8" locale is used as fallback.
#if !defined(WIN32) && !defined(MAC_OSX) && !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__NetBSD__)
    try {
        std::locale(""); // Raises a runtime error if current locale is invalid
    } catch (const std::runtime_error&) {
        setenv("LC_ALL", "C.UTF-8", 1);
    }
#elif defined(WIN32)
    // Set the default input/output charset is utf-8
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
#endif

#ifndef WIN32
    constexpr mode_t private_umask = 0077;
    umask(private_umask);
#endif
}

bool SetupNetworking()
{
#ifdef WIN32
    // Initialize Windows Sockets
    WSADATA wsadata;
    int ret = WSAStartup(MAKEWORD(2,2), &wsadata);
    if (ret != NO_ERROR || LOBYTE(wsadata.wVersion ) != 2 || HIBYTE(wsadata.wVersion) != 2)
        return false;
#endif
    return true;
}

int GetNumCores()
{
    return std::thread::hardware_concurrency();
}

// Obtain the application startup time (used for uptime calculation)
int64_t GetStartupTime()
{
    return nStartupTime;
}

void ScheduleBatchPriority()
{
#ifdef SCHED_BATCH
    const static sched_param param{};
    const int rc = pthread_setschedparam(pthread_self(), SCHED_BATCH, &param);
    if (rc != 0) {
        LogPrintf("Failed to pthread_setschedparam: %s\n", SysErrorString(rc));
    }
#endif
}
