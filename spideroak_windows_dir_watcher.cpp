// spideroak_windows_fsevents.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "stdio.h"
#include "shellapi.h"
#include "spideroak_windows_dir_watcher.h"
#include "psapi.h" // for EnumProcesses


#define MAX_DIRECTORIES 50   // The most directories we will watch
#define MAX_EXCLUDES 50      // The most directories we will exclude
#define MAX_HANDLES 64       // The most handles of  all kinds that we will wait for
#define PATH_BUFFER_SIZE 4096
#define CHANGES_BUFFER_SIZE 64 * 1024
#define ERROR_BUFFER_SIZE 4096

typedef struct  { 
    OVERLAPPED  overlap; 
    HANDLE      hDirectory; 
    DWORD       directory_index;
    BYTE        changes_buffer[CHANGES_BUFFER_SIZE];
} DIR_WATCHER, *DIR_WATCHER_P;

typedef wchar_t DIR_PATH[PATH_BUFFER_SIZE+1];

static const DWORD DIRECTORY_CHANGES_FILTER = 
    FILE_NOTIFY_CHANGE_FILE_NAME 
|   FILE_NOTIFY_CHANGE_DIR_NAME 
|   FILE_NOTIFY_CHANGE_ATTRIBUTES
|   FILE_NOTIFY_CHANGE_SIZE
|   FILE_NOTIFY_CHANGE_LAST_WRITE
|   FILE_NOTIFY_CHANGE_LAST_ACCESS
|   FILE_NOTIFY_CHANGE_CREATION;

static const DWORD valid_action = 
      FILE_ACTION_ADDED 
    | FILE_ACTION_REMOVED 
    | FILE_ACTION_MODIFIED 
    | FILE_ACTION_RENAMED_OLD_NAME 
    | FILE_ACTION_RENAMED_NEW_NAME; 
static wchar_t wcs_buffer[PATH_BUFFER_SIZE];
static char mbcs_buffer[PATH_BUFFER_SIZE];
static wchar_t temp_file_path[PATH_BUFFER_SIZE];
static DWORD notification_sequence = 0;
static wchar_t notification_file_path[PATH_BUFFER_SIZE];

static HANDLE handle_array[MAX_HANDLES];
static DIR_WATCHER_P dir_watchers[MAX_DIRECTORIES];
static DIR_PATH dir_paths[MAX_DIRECTORIES];
static DIR_PATH exclude_paths[MAX_EXCLUDES];
static DIR_PATH error_path;
static FILE * error_file = NULL;
static wchar_t error_buffer[ERROR_BUFFER_SIZE+1];

//-----------------------------------------------------------------------------
static void report_error(LPCWSTR message,  DWORD error_code) {
//-----------------------------------------------------------------------------
    LPWSTR lpMsgBuf;
    DWORD message_size;

    message_size = FormatMessage( 
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        error_code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
        (LPWSTR) &lpMsgBuf,
        0,
        NULL 
    );

    _wfopen_s(&error_file, error_path, L"w");
    fwprintf(error_file, L"%s 0x%04X %s\n",  message, error_code, lpMsgBuf);
    fclose(error_file);

    // Free the buffer.
    LocalFree(lpMsgBuf);

} // static void report_error(LPCWSTR message,  DWORD error_code)

//-----------------------------------------------------------------------------
static DWORD load_paths_to_array(DIR_PATH *path_array, DWORD max_array_size, LPCTSTR path) {
//-----------------------------------------------------------------------------
    FILE * stream_p;
    DWORD entry_index;
    LPWSTR newline_p;

    if (_wfopen_s(&stream_p, path, L"r")) {
    	_wfopen_s(&error_file, error_path, L"w");
	_wcserror_s(error_buffer, sizeof error_buffer, errno); 
    	fwprintf(
	    error_file, 
	    L"_wfopen(%s) failed: (%d) %s\n",  
	    path,
	    errno,
	    error_buffer 
	);
    	fclose(error_file);
        ExitProcess(2);
    }
    for (entry_index=0; TRUE; entry_index++) {

        if (entry_index >= max_array_size) {
    	    _wfopen_s(&error_file, error_path, L"w");
    	    fwprintf(
	        error_file, 
	        L"_load_paths_to_array: too many paths (%d)\n",  
	        entry_index
	    );
    	    fclose(error_file);
            ExitProcess(7);
        }

        if (NULL == fgetws(path_array[entry_index], PATH_BUFFER_SIZE, stream_p)) {
            break;
        }

        newline_p = wcschr(path_array[entry_index], L'\n');
        if (newline_p != NULL) {
            *newline_p = L'\0'; 
        }
    }

    fclose(stream_p);

    return entry_index;

} // load_paths_to_array

//-----------------------------------------------------------------------------
static DIR_WATCHER_P start_watching_directory(
    HANDLE hDirectory, 
    DWORD directory_index
) {
//-----------------------------------------------------------------------------
    DIR_WATCHER_P dir_watcher_p;
    BOOL start_read_result;

    dir_watcher_p = (DIR_WATCHER_P) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DIR_WATCHER));
    dir_watcher_p->overlap.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    dir_watcher_p->hDirectory = hDirectory;
    dir_watcher_p->directory_index = directory_index;

    start_read_result = ReadDirectoryChangesW(
        dir_watcher_p->hDirectory,                    // HANDLE hDirectory,
        dir_watcher_p->changes_buffer,                // LPVOID lpBuffer,
        sizeof(dir_watcher_p->changes_buffer),        // DWORD nBufferLength,
        TRUE,                                         // BOOL bWatchSubtree,
        DIRECTORY_CHANGES_FILTER,                     // DWORD dwNotifyFilter,
        NULL,                                         // LPDWORD lpBytesReturned,
        (LPOVERLAPPED) dir_watcher_p,                 // LPOVERLAPPED lpOverlapped,
        NULL                                          // LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    );

    if (!start_read_result) {
        report_error(L"ReadDirectoryChangesW", GetLastError());
        ExitProcess(10);
    }

    return dir_watcher_p;
} // start_watching_directory

//------------------------------------------------------------------------------
static BOOL parent_is_gone(DWORD parent_pid) {
//------------------------------------------------------------------------------
    static DWORD process_ids[4096];
    DWORD bytes_returned;
    BOOL enum_result;
    DWORD process_count;
    DWORD i;

    enum_result = EnumProcesses(
        process_ids,
        sizeof process_ids,
        &bytes_returned
    );
    if (!enum_result) {
        report_error(L"EnumProcesses", GetLastError());
        ExitProcess(25);
    }
    process_count = bytes_returned / sizeof(DWORD);
    for (i=0; i < process_count; i++) {
        if (process_ids[i] == parent_pid) {
            return FALSE;
        }
    }

    return TRUE;

} // static BOOL parent_is_gone(DWORD parent_pid) {

//-----------------------------------------------------------------------------
// a safe replacement for wcsrchr which has an embarassing tendency to run
// past the start of the string.
static size_t safe_search_last_instance(LPCWSTR str_p, wchar_t target, size_t length) {
//-----------------------------------------------------------------------------
    size_t i;

    if (0 == length) {
        return -1;
    }

    for (i=length-1; i >= 0; i--) {
        if (*(str_p + i) == target) {
            return i;
        }
    }

    return -1;
}

//-----------------------------------------------------------------------------
static void process_dir_watcher_results(
    LPBYTE          buffer,
    DWORD           buffer_size,
    LPCWSTR         dir_path,
    DWORD           exclude_count,
    LPCWSTR         notification_path) {
//-----------------------------------------------------------------------------
    HANDLE hChangeLog;
    PFILE_NOTIFY_INFORMATION buffer_p;
    DWORD buffer_index;
    BOOL more;
    size_t slash_index;
    int compare_result;
    BOOL exclude;
    DWORD i;
    size_t converted_chars;
    DWORD bytes_to_write;
    DWORD bytes_written;
    BOOL write_succeeded;

    hChangeLog = INVALID_HANDLE_VALUE;

    more = TRUE;
    buffer_index = 0;
    while (more) {

        if ((buffer_index+sizeof(FILE_NOTIFY_INFORMATION)) > buffer_size) {
    	    _wfopen_s(&error_file, error_path, L"w");
    	    fwprintf(
	        error_file, 
	        L"process_dir_watcher_results buffer overrun %d %d\n",  
	        buffer_index,
	        buffer_size
	    );
    	    fclose(error_file);
            ExitProcess(18);
        }

        buffer_p = (PFILE_NOTIFY_INFORMATION) &buffer[buffer_index];

        if ((buffer_p->Action & valid_action) == 0) {
            if (0 == buffer_p->NextEntryOffset) {
                more = FALSE;
            } else {
                buffer_index += buffer_p->NextEntryOffset;
            }
            continue;
        }

	memset(wcs_buffer, '\0', sizeof wcs_buffer);
        wsprintf(          
            wcs_buffer,                     // LPTSTR pszDest,
            L"%s\\%s\n",                    // LPCTSTR pszFormat 
            dir_path,
            buffer_p->FileName
        );

        // We must check for excludes before pruning the directory
        exclude = FALSE;
        for (i=0; i < exclude_count; i++) {
            compare_result = _wcsnicmp(
                (LPCWSTR) wcs_buffer,
                (LPCWSTR) exclude_paths[i],
                wcslen(exclude_paths[i]) 
            );
            if (0 == compare_result) {
                exclude = TRUE;
                break;
            }
        }

        if (exclude) {
            if (0 == buffer_p->NextEntryOffset) {
                more = FALSE;
            } else {
                buffer_index += buffer_p->NextEntryOffset;
            }
            continue;
        }

        // We want the directory where the event took place, for consistency with OSX.
        // So, we find the last '\' (if any) in the string and replace it with '\0'
        slash_index = safe_search_last_instance(wcs_buffer, L'\\', wcslen(wcs_buffer));
        if (slash_index != -1) {
            wcs_buffer[slash_index] = L'\n';
            wcs_buffer[slash_index+1] = L'\0';
        }

        converted_chars = WideCharToMultiByte(
            CP_UTF8, 
            0, 
            wcs_buffer, 
            (int) wcslen(wcs_buffer), 
            mbcs_buffer, 
            PATH_BUFFER_SIZE, 
            NULL, 
            NULL 
        );
        if (converted_chars == 0) {
            report_error(L"WideCharToMultiByte", GetLastError());
            ExitProcess(20);
        }

        if (INVALID_HANDLE_VALUE == hChangeLog) {
            // open the change log file
            wsprintf(          
                temp_file_path,                 // LPTSTR pszDest,
                L"%s\\temp",                    // LPCTSTR pszFormat 
                notification_path
            );

            hChangeLog = CreateFile(
                temp_file_path,           // LPCTSTR lpFileName,
                GENERIC_WRITE,            // DWORD dwDesiredAccess,
                0,                        // DWORD dwShareMode,
                NULL,                     // LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                CREATE_ALWAYS,            // DWORD dwCreationDisposition,
                FILE_ATTRIBUTE_NORMAL,    // DWORD dwFlagsAndAttributes,
                NULL                      // HANDLE hTemplateFile
            );

            if (INVALID_HANDLE_VALUE == hChangeLog) {
            	report_error(L"CreateFile temp changelog", GetLastError());
                ExitProcess(21);
            }
        }

        bytes_to_write = (DWORD) strlen(mbcs_buffer);
        bytes_written = 0;
        write_succeeded = WriteFile(
            hChangeLog,             // HANDLE hFile,
            mbcs_buffer,            // LPCVOID lpBuffer,
            bytes_to_write,         // DWORD nNumberOfBytesToWrite,
            &bytes_written,         // LPDWORD lpNumberOfBytesWritten,
            NULL                    // LPOVERLAPPED lpOverlapped
        );
        if (!write_succeeded) {
            report_error(L"WriteFile temp changelog", GetLastError());
            ExitProcess(22);
        }

        if (0 == buffer_p->NextEntryOffset) {
            more = FALSE;
        } else {
            buffer_index += buffer_p->NextEntryOffset;
        }
    } // while (more)

    if (hChangeLog != INVALID_HANDLE_VALUE) {
        CloseHandle(hChangeLog);

        notification_sequence++;
        wsprintf(          
            notification_file_path,         // LPTSTR pszDest,
            L"%s\\%08d.txt",                // LPCTSTR pszFormat 
            notification_path,
            notification_sequence
        );
        if (_wrename(temp_file_path, notification_file_path) != 0) {
    	    _wfopen_s(&error_file, error_path, L"w");
	    _wcserror_s(error_buffer, sizeof error_buffer, errno); 
    	    fwprintf(
	        error_file, 
	        L"_wrename(%s, %s) failed: (%d) %s\n",  
	        temp_file_path,
		notification_file_path,
	        errno,
	        error_buffer 
	    );
    	    fclose(error_file);
            ExitProcess(24);
        }
    }

} // static void process_dir_watcher_results(

//------------------------------------------------------------------------------
int APIENTRY _tWinMain(
    HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPTSTR    lpCmdLine,
    int       nCmdShow
) {
//------------------------------------------------------------------------------
    LPTSTR command_line = GetCommandLine();
    int num_args;
    int parent_pid;
    DWORD directory_count;
    DWORD exclude_count;
    LPWSTR * args_p;
    HANDLE hDirectory;
    DWORD handle_count;
    DWORD directory_index;
    DWORD wait_result;
    DWORD handle_index;
    DIR_WATCHER_P dir_watcher_p;
    DWORD timer_index;
    LARGE_INTEGER timer_start;
    LONG timer_period;
    BOOL set_result;
    BOOL get_successful;
    DWORD bytes_returned = 0;

    args_p = CommandLineToArgvW(command_line, &num_args);

    if (num_args != 5) {
        return 1;
    }

    parent_pid = _wtoi(args_p[1]);

    wsprintf(error_path, L"%s\\error.txt", args_p[4]);
    memset(error_buffer, '\0', sizeof wcs_buffer);

    directory_count = load_paths_to_array(dir_paths, MAX_DIRECTORIES, args_p[2]);
    if (0 == directory_count) {
        return 0;
    }

    exclude_count = load_paths_to_array(exclude_paths, MAX_EXCLUDES, args_p[3]);

    handle_count = 0;
    for (directory_index=0; directory_index < directory_count; directory_index++) {

        hDirectory = CreateFile(
            dir_paths[directory_index],                         // LPCTSTR lpFileName,
            FILE_LIST_DIRECTORY,                                // DWORD dwDesiredAccess,
            FILE_SHARE_READ | FILE_SHARE_WRITE,                 // DWORD dwShareMode,
            NULL,                                               // LPSECURITY_ATTRIBUTES lpSecurityAttributes,
            OPEN_EXISTING,                                      // DWORD dwCreationDisposition,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,  // DWORD dwFlagsAndAttributes,
            NULL                                                // HANDLE hTemplateFile
        );

        // 2009-03-11 dougfort -- if we can't create this file, assume it is a top-level directory
        // which no longer exists; so ignore it and move on.
        if (INVALID_HANDLE_VALUE == hDirectory) {
            report_error(L"CreateFile", GetLastError());
            continue;
        }

        dir_watchers[handle_count] = start_watching_directory(hDirectory, directory_index);
        handle_array[handle_count] = dir_watchers[handle_count]->overlap.hEvent;
        handle_count++;

    } //   for (handle_count=0; tail_p != NULL; handle_count++)

    // If we don't have any valid directories to watch, there's no point in running
    if (0 == handle_count) {
        return 0;
    }

    handle_array[handle_count] = CreateWaitableTimer(
        NULL,
        FALSE,
        L"orphan_timer"
    );
    if (NULL == handle_array[handle_count]) {
        report_error(L"CreateWaitableTimer orphan timer", GetLastError());
        ExitProcess(23);
    }

    timer_index = handle_count;
    handle_count++;

    memset(&timer_start, '\0', sizeof timer_start);
    timer_period = 3 * 1000; //3 seconds
    set_result = SetWaitableTimer(
        handle_array[timer_index],
        &timer_start,
        timer_period,
        NULL,
        NULL,
        FALSE // do not restore a system in suspended power conservation mode 
    );    
    if (!set_result) {
        report_error(L"SetWaitableTimer orphan timer", GetLastError());
        ExitProcess(13);
    }

    while (TRUE) {

        wait_result = WaitForMultipleObjects(
            handle_count,  // DWORD nCount,
            handle_array,  //const HANDLE* lpHandles,
            FALSE,         // BOOL bWaitAll,
            INFINITE       // DWORD dwMilliseconds
        );

        if (WAIT_FAILED == wait_result) {
            report_error(L"WaitForMultipleObjects", GetLastError());
            ExitProcess(13);
        }

        handle_index = wait_result - WAIT_OBJECT_0;
        if (handle_index == timer_index) {
            if (parent_is_gone(parent_pid)) {
                break;
            }
            continue;
        }

        dir_watcher_p = dir_watchers[handle_index];

        get_successful = GetOverlappedResult(
            dir_watcher_p->hDirectory,           // HANDLE hFile,
            (LPOVERLAPPED) dir_watcher_p,        // LPOVERLAPPED lpOverlapped,
            &bytes_returned,                     // LPDWORD lpNumberOfBytesTransferred,
            FALSE                                // BOOL bWait
        );    
    
        if (!get_successful) {
            report_error(L"GetOverlappedResult", GetLastError());
            ExitProcess(15);
        }

        // start a new watcher immediately
        dir_watchers[handle_index] = start_watching_directory(
            dir_watcher_p->hDirectory, 
            dir_watcher_p->directory_index
        );
        handle_array[handle_index] = dir_watchers[handle_index]->overlap.hEvent;

        // then report the results of the one that just completed
        if (bytes_returned > 0) {
            process_dir_watcher_results(
                dir_watcher_p->changes_buffer, 
                bytes_returned,
                dir_paths[dir_watcher_p->directory_index], 
                exclude_count, 
                args_p[4]
            );
        }

        CloseHandle(dir_watcher_p->overlap.hEvent);
        HeapFree(GetProcessHeap(), 0, dir_watcher_p);

    } // while (TRUE) {

    for (handle_index=0; handle_index < timer_index; ++handle_index) {
        CloseHandle(dir_watchers[handle_index]->hDirectory);
        CloseHandle(dir_watchers[handle_index]->overlap.hEvent);
        HeapFree(GetProcessHeap(), 0, dir_watchers[handle_index]);
    }

    // We get here if we think the parent is gone
    return 0;

} // _tWinMain
