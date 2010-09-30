// spideroak_windows_fsevents.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "stdio.h"
#include "shellapi.h"
#include "spideroak_windows_dir_watcher.h"
#include "psapi.h" // for EnumProcesses


#define PATH_BUFFER_SIZE 4096
#define CHANGES_BUFFER_SIZE 128 * 1024
#define ERROR_BUFFER_SIZE 4096
#define TIMEOUT_MILLESECONDS 2000
#define PARENT_CHECK_COUNT 100

typedef wchar_t DIR_PATH[PATH_BUFFER_SIZE+1];

struct watch_entry {
    OVERLAPPED            overlap; 
    DIR_PATH              dir_path;
    HANDLE                hDirectory; 
    BYTE                  changes_buffer[CHANGES_BUFFER_SIZE];
    struct watch_entry   *next_p;
}; 

struct exclude_entry {
    DIR_PATH              dir_path;
    struct exclude_entry  *next_p;
}; 

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
static wchar_t file_name_buffer[PATH_BUFFER_SIZE];
static wchar_t wcs_buffer[PATH_BUFFER_SIZE];
static wchar_t long_name_buffer[PATH_BUFFER_SIZE];
static char mbcs_buffer[PATH_BUFFER_SIZE];
static wchar_t temp_file_path[PATH_BUFFER_SIZE];
static DWORD notification_sequence = 0;
static wchar_t notification_file_path[PATH_BUFFER_SIZE];

static DIR_PATH error_path;
static FILE * error_file = NULL;
static wchar_t error_buffer[ERROR_BUFFER_SIZE+1];
static struct watch_entry *watch_entry_list_p = NULL;
static struct exclude_entry *exclude_entry_list_p = NULL;

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
// a safe replacement for wcsrchr which has an embarassing tendency to run
// past the start of the string.
static size_t safe_search_last_instance(
    LPCWSTR str_p, wchar_t target, size_t length
) {
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
static start_watch(struct watch_entry * watch_entry_p) {
//-----------------------------------------------------------------------------
    BOOL start_read_result;

    memset(&watch_entry_p->overlap, '\0', sizeof watch_entry_p->overlap);	
    memset(
        &watch_entry_p->changes_buffer, 
        '\0', 
        sizeof watch_entry_p->changes_buffer
    );	

    // start an overlapped 'read' to look for a filesystem change
    start_read_result = ReadDirectoryChangesW(
        watch_entry_p->hDirectory,
        watch_entry_p->changes_buffer,
        sizeof(watch_entry_p->changes_buffer),
        TRUE,
        DIRECTORY_CHANGES_FILTER,
        NULL,
        (LPOVERLAPPED) watch_entry_p,
        NULL
    );

    if (!start_read_result) {
        report_error(L"ReadDirectoryChangesW", GetLastError());
        ExitProcess(10);
    }

} // start_watch

//-----------------------------------------------------------------------------
static void load_paths_to_watch(LPCTSTR path, HANDLE completion_port_h) {
//-----------------------------------------------------------------------------
    FILE * stream_p;
    wchar_t *get_result;
    HANDLE create_result;
    size_t char_index;
    struct watch_entry **link_p;
    struct watch_entry * next_p;

    if (_wfopen_s(&stream_p, path, L"r")) {
        _wfopen_s(&error_file, error_path, L"w");
        _wcserror_s(error_buffer, sizeof error_buffer/sizeof(wchar_t) , errno); 
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

    link_p = &watch_entry_list_p;
   
    while (1) {

        // create a watch entry
        next_p = (struct watch_entry *) HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(struct watch_entry)
        );

        // read in the path to watch from config.txt
        get_result = \
            fgetws(next_p->dir_path, PATH_BUFFER_SIZE, stream_p);

        if (NULL == get_result) {
            if (0 == ferror(stream_p)) {
                HeapFree(GetProcessHeap(), 0, next_p);
                break;
            } 
            _wfopen_s(&error_file, error_path, L"w");
            _wcserror_s(
               error_buffer, sizeof error_buffer/sizeof(wchar_t) , errno
            ); 
            fwprintf(
                error_file, 
                L"fgetws(%s) failed: (%d) %s\n",  
                path,
                errno,
                error_buffer 
            );
            fclose(error_file);
            ExitProcess(2);
        }

        // clean out the newline, if there is one
        char_index = safe_search_last_instance(
              next_p->dir_path, 
              L'\n', 
              wcslen(next_p->dir_path)
        );
        if (char_index != -1) {
            next_p->dir_path[char_index] = L'\0'; 
        }

        if (wcslen(next_p->dir_path) == 0) {
           continue;
        }

        // 2020-09-05 dougfort -- we don't clean out trailing slash here
        // because if they are backing up something like c:\\, we need
        // the trailing slash. This will come back to bite us when we are
        // checking for excludes

        // open a file handle to watch the directory in overlapped mode
        next_p->hDirectory = CreateFile(
            next_p->dir_path,
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            NULL
        );

        // 2009-03-11 dougfort -- if we can't create this file, 
        // assume it is a top-level directory
        // which no longer exists; so ignore it and move on.
        if (INVALID_HANDLE_VALUE == next_p->hDirectory) {
            report_error(L"CreateFile", GetLastError());
            continue;
        }

        // add this file handle to the IO Complete port
        create_result = CreateIoCompletionPort(
            next_p->hDirectory,         // FileHandle,
            completion_port_h,          // ExistingCompletionPort,
            0,                          // CompletionKey,
            0                           // NumberOfConcurrentThreads
        );

        if (NULL == create_result) {
            report_error(L"CreateIOCompletionPort (add)", GetLastError());
            ExitProcess(102);
        }

        if (create_result != completion_port_h) {
            ExitProcess(103);
        }

        start_watch(next_p);

        // add this entry to the list
        *link_p = next_p;

        // point to the new entry's next pointer 
        link_p = &(*link_p)->next_p;
    } // while(1)

    fclose(stream_p);

} // load_paths_to_watch

//-----------------------------------------------------------------------------
static void load_paths_to_exclude(LPCTSTR path) {
//-----------------------------------------------------------------------------
    FILE * stream_p;
    wchar_t *get_result;
    size_t path_len;
    size_t char_index;
    struct exclude_entry **link_p;
    struct exclude_entry * next_p;

    if (_wfopen_s(&stream_p, path, L"r")) {
        _wfopen_s(&error_file, error_path, L"w");
        _wcserror_s(error_buffer, sizeof error_buffer/sizeof(wchar_t), errno); 
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

    link_p = &exclude_entry_list_p;
   
    while (1) {

        // create an exclude entry
        next_p = (struct exclude_entry *) HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(struct exclude_entry)
        );

        // read in the path to watch from config.txt
        get_result = \
            fgetws(next_p->dir_path, PATH_BUFFER_SIZE, stream_p);

        if (NULL == get_result) {
            if (0 == ferror(stream_p)) {
                HeapFree(GetProcessHeap(), 0, next_p);
                break;
            } 
            _wfopen_s(&error_file, error_path, L"w");
            _wcserror_s(
               error_buffer, sizeof error_buffer/sizeof(wchar_t), errno
            ); 
            fwprintf(
                error_file, 
                L"fgetws(%s) failed: (%d) %s\n",  
                path,
                errno,
                error_buffer 
            );
            fclose(error_file);
            ExitProcess(2);
        }

        path_len = wcslen(next_p->dir_path);

        // clean out the newline, if there is one
        char_index = safe_search_last_instance(
            next_p->dir_path, L'\n', path_len
        );
        if (char_index != -1) {
            next_p->dir_path[char_index] = L'\0';
            path_len -= 1; 
        }
   
        // add this entry to the list
        *link_p = next_p;

        // point to the new entry's next pointer 
        link_p = &(*link_p)->next_p;
    } // while(1)

    fclose(stream_p);

} // load_paths_to_exclude

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
static void process_dir_watcher_results(
    LPBYTE          buffer,
    DWORD           buffer_size,
    LPCWSTR         dir_path,
    LPCWSTR         notification_path) {
//-----------------------------------------------------------------------------
    HANDLE hChangeLog;
    PFILE_NOTIFY_INFORMATION buffer_p;
    DWORD buffer_index;
    BOOL more;
    size_t dir_path_len;
    size_t path_len;
    size_t slash_index;
    int compare_result;
    BOOL exclude;
    struct exclude_entry * exclude_entry_p;
    size_t converted_chars;
    DWORD bytes_to_write;
    DWORD bytes_written;
    BOOL write_succeeded;
    DWORD long_name_result;
    DWORD error_code;

    hChangeLog = INVALID_HANDLE_VALUE;

    dir_path_len = wcslen(dir_path);

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

        memset(file_name_buffer, '\0', sizeof file_name_buffer);
        wcscpy_s(file_name_buffer, buffer_p->FileNameLength, buffer_p->FileName);

        memset(wcs_buffer, '\0', sizeof wcs_buffer);

        // 2010-09-05 dougfort -- if the dir_path ends in a slash 
        // (probably something like c:\) then we don't want to
        // interpolate another slash
        if (dir_path[dir_path_len-1] == L'\\') {
           wsprintf(          
               wcs_buffer,                     // LPTSTR pszDest,
               L"%s%s",                        // LPCTSTR pszFormat 
               dir_path,
               file_name_buffer
           );
        } else {
           wsprintf(          
               wcs_buffer,                     // LPTSTR pszDest,
               L"%s\\%s",                      // LPCTSTR pszFormat 
               dir_path,
               file_name_buffer
           );
        }

        // We must check for excludes before pruning the directory
        exclude = FALSE;
        for (
            exclude_entry_p=exclude_entry_list_p; 
            exclude_entry_p != NULL; 
            exclude_entry_p = exclude_entry_p->next_p
        ) {
            compare_result = _wcsnicmp(
                (LPCWSTR) wcs_buffer,
                (LPCWSTR) exclude_entry_p->dir_path,
                wcslen(exclude_entry_p->dir_path) 
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

        // We want the directory where the event took place, 
        // for consistency with OSX.
        // So, we find the last '\' (if any) in the string 
        // and replace it with '\0'
        // 2010-09-06 dougfort -- if the buffer ends with a slash,
        // such as c:\, we want to keep it.
        path_len = wcslen(wcs_buffer);
        if (wcs_buffer[path_len-1] != L'\\') {
             slash_index = safe_search_last_instance(
                 wcs_buffer, L'\\', path_len
             );
             if (slash_index != -1) {
                 wcs_buffer[slash_index] = L'\0';
             }
        }

        // 2010-05-13 dougfort -- we're picking up short names here,
        // apparently some old applications trigger the event with
        // a short name. We have to do the long name check here, 
        // because the target must exist
        memset(long_name_buffer, '\0', sizeof long_name_buffer);
        long_name_result = GetLongPathNameW(
            wcs_buffer,
            long_name_buffer,
            sizeof long_name_buffer/sizeof(wchar_t) 
        );
        if (!long_name_result) {
            error_code = GetLastError();
            switch (error_code) {
               // do not abort if the directory has vanished
               case ERROR_FILE_NOT_FOUND: 
               case ERROR_PATH_NOT_FOUND:
                   if (0 == buffer_p->NextEntryOffset) {
                       more = FALSE;
                   } else {
                       buffer_index += buffer_p->NextEntryOffset;
                   }
                   continue;
               // 2010-07-07 dougfort -- I think we're getting these from
               // long names which contain characters not allowed in
               // short names. So we just pass on the name
               case ERROR_INVALID_NAME:
               // 2010-08-17 dougfort -- I don't know why we're getting
               // these, but let's just pass on the original name, it's
               // probably not a short name.
               case ERROR_ACCESS_DENIED:
                  wcscpy_s(
                     long_name_buffer, 
                     sizeof long_name_buffer/sizeof(wchar_t), 
                     wcs_buffer
                  );
                  break;
               default:
                  report_error(L"GetLongPathNameW", error_code);
                  ExitProcess(21);
            } // switch
        }

        wcscat_s(
            long_name_buffer, sizeof long_name_buffer/sizeof(wchar_t), L"\n"
        );

        memset(mbcs_buffer, '\0', sizeof mbcs_buffer);
        converted_chars = WideCharToMultiByte(
            CP_UTF8, 
            0, 
            long_name_buffer, 
            (int) wcslen(long_name_buffer), 
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
                NULL,                     // LPSECURITY_ATTRIBUTES
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
            _wcserror_s(
               error_buffer, sizeof error_buffer/sizeof(wchar_t), errno
            ); 
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

//-----------------------------------------------------------------------------
int APIENTRY _tWinMain(
    HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPTSTR    lpCmdLine,
    int       nCmdShow
) {
//-----------------------------------------------------------------------------
    LPTSTR command_line = GetCommandLine();
    int num_args;
    int parent_pid;
    HANDLE completion_port_h;
    LPWSTR * args_p;
    BOOL get_successful;
    DWORD bytes_returned;
    struct watch_entry * watch_entry_p;
    DWORD completion_key;
    int loop_count;

    args_p = CommandLineToArgvW(command_line, &num_args);

    if (num_args != 5) {
        return 1;
    }

    parent_pid = _wtoi(args_p[1]);

    wsprintf(error_path, L"%s\\error.txt", args_p[4]);
    memset(error_buffer, '\0', sizeof wcs_buffer);

    // create the basic completion port
    completion_port_h = CreateIoCompletionPort(
        INVALID_HANDLE_VALUE,   // FileHandle,
        NULL,                   // ExistingCompletionPort,
        0,                      // CompletionKey,
        0                       // NumberOfConcurrentThreads
    );
    if (NULL == completion_port_h) {
        report_error(L"CreateIoCompletionPort", GetLastError());
        ExitProcess(100);
    }

    load_paths_to_watch(args_p[2], completion_port_h);
    if (NULL == watch_entry_list_p) {
        return 0;
    }

    load_paths_to_exclude(args_p[3]);

    loop_count = 0;
    while (TRUE) {

       loop_count += 1;

        watch_entry_p = NULL;
        get_successful = GetQueuedCompletionStatus(
            completion_port_h,
            &bytes_returned,
            &completion_key,
            (LPOVERLAPPED *) &watch_entry_p,
            TIMEOUT_MILLESECONDS
        );

        if (!get_successful) {
            if (NULL == watch_entry_p) { 
                // timeout: make sure our parent is still running
                if (parent_is_gone(parent_pid)) {
                    break;
                } else {
                    continue;
                }
            }
            report_error(L"GetQueuedCompletionStatus", GetLastError());
            ExitProcess(115);
        }

        // report the results of the one that just completed
        if (bytes_returned > 0) {
            process_dir_watcher_results(
                watch_entry_p->changes_buffer, 
                bytes_returned,
                watch_entry_p->dir_path, 
                args_p[4]
            );
        }

        // start a new watch
        start_watch(watch_entry_p);

        if (loop_count % PARENT_CHECK_COUNT == 0) {
             if (parent_is_gone(parent_pid)) {
                 break;
             }
        }

    } // while (TRUE) {

    // We get here if we think the parent is gone
    return 0;

} // _tWinMain
