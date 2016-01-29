// spideroak_windows_fsevents.cpp : Defines the entry point for the application.
//

#include "stddef.h"
#include "stdafx.h"
#include "stdio.h"
#include "shellapi.h"

#define PATH_BUFFER_SIZE 32768
/* Change buffer cannot be larger than 64k for network file transactions
	(UNC paths or drives mapped to shares)
*/
#define CHANGES_BUFFER_SIZE 64 * 1024
#define ERROR_BUFFER_SIZE 4096
#define TIMEOUT_MILLESECONDS 1000
#define PARENT_CHECK_COUNT 50

typedef wchar_t DIR_PATH[PATH_BUFFER_SIZE];

struct watch_entry {
    OVERLAPPED            overlap; 
    wchar_t *             dir_path;
	size_t                dir_path_len;
    HANDLE                hDirectory; 
    BYTE *                changes_buffer;
    struct watch_entry   *next_p;
}; 

struct exclude_entry {
    wchar_t *             dir_path;
	size_t                dir_path_len;
    struct exclude_entry  *next_p;
}; 

static const DWORD DIRECTORY_CHANGES_FILTER = 
    FILE_NOTIFY_CHANGE_FILE_NAME 
|   FILE_NOTIFY_CHANGE_DIR_NAME 
|   FILE_NOTIFY_CHANGE_ATTRIBUTES
|   FILE_NOTIFY_CHANGE_SIZE
|   FILE_NOTIFY_CHANGE_LAST_WRITE
|   FILE_NOTIFY_CHANGE_CREATION;
/*
	Don't need last access, as we don't track it and it creates a lot of overhead
	with false hits
 |   FILE_NOTIFY_CHANGE_LAST_ACCESS
*/

static wchar_t relative_file_name[PATH_BUFFER_SIZE];
static wchar_t full_file_name[PATH_BUFFER_SIZE];
static char mbcs_buffer[PATH_BUFFER_SIZE];
static wchar_t temp_file_path[PATH_BUFFER_SIZE];
static DWORD notification_sequence = 0;
static wchar_t * notification_path;
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

    _wfopen_s(&error_file, error_path, L"a+, ccs=UTF-8");
    fwprintf(error_file, L"%s 0x%04X %s\n",  message, error_code, lpMsgBuf);
    fclose(error_file);

    // Free the buffer.
    LocalFree(lpMsgBuf);

} // static void report_error(LPCWSTR message,  DWORD error_code)


//-----------------------------------------------------------------------------
static void start_watch(struct watch_entry * watch_entry_p) {
//-----------------------------------------------------------------------------
    BOOL start_read_result;

    memset(&watch_entry_p->overlap, 0, sizeof(watch_entry_p->overlap));	

    // start an overlapped 'read' to look for a filesystem change
    start_read_result = ReadDirectoryChangesW(
        watch_entry_p->hDirectory,
        watch_entry_p->changes_buffer,
        CHANGES_BUFFER_SIZE,
        TRUE,
        DIRECTORY_CHANGES_FILTER,
        NULL,
        (LPOVERLAPPED) watch_entry_p,
        NULL
    );

    if (!start_read_result) {
		DWORD err = GetLastError();
        report_error(L"ReadDirectoryChangesW", err);
		/* This error is reported for a handle to a file, meaning a folder has been
			recreated as a file after it was selected for backup.
		*/
		if (err != ERROR_INVALID_PARAMETER)
			ExitProcess(10);
    }

} // start_watch

//-----------------------------------------------------------------------------
static void load_paths_to_watch(LPCTSTR path, HANDLE completion_port_h) {
//-----------------------------------------------------------------------------
    FILE * stream_p;
    wchar_t *get_result;
    HANDLE create_result;
    size_t line_len;
    struct watch_entry **link_p;
    struct watch_entry * next_p;

    if (_wfopen_s(&stream_p, path, L"r, ccs=UTF-8")) {
        _wfopen_s(&error_file, error_path, L"w");
        _wcserror_s(error_buffer, ARRAYSIZE(error_buffer), errno); 
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
		if (next_p == NULL){
			report_error(L"HeapAlloc failed to allocate memory", GetLastError());
			ExitProcess(200);
			}
        // read in the path to watch from config.txt
        get_result = \
            fgetws(full_file_name, ARRAYSIZE(full_file_name), stream_p);

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
        line_len = wcslen(full_file_name);
		if (line_len && full_file_name[line_len-1] == L'\n'){
			full_file_name[line_len-1] = L'\0';
			line_len--;
			}
        if (full_file_name[0] == L'\0')
           continue;
		next_p->dir_path_len = line_len;
		next_p->dir_path = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
			(line_len + 1) * sizeof(wchar_t));
		if (next_p->dir_path == NULL){
			report_error(L"HeapAlloc failed to allocate memory", GetLastError());
			ExitProcess(201);
		}
		wcsncpy_s(next_p->dir_path, line_len+1, full_file_name, line_len);
		next_p->changes_buffer = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
			CHANGES_BUFFER_SIZE);
		if (next_p->changes_buffer == NULL){
			report_error(L"HeapAlloc failed to allocate memory", GetLastError());
			ExitProcess(202);
		}
        // 2020-09-05 dougfort -- we don't clean out trailing slash here
        // because if they are backing up something like c:\\, we need
        // the trailing slash. This will come back to bite us when we are
        // checking for excludes

        // open a file handle to watch the directory in overlapped mode
        next_p->hDirectory = CreateFile(
            next_p->dir_path,
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
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
    size_t line_len;
    struct exclude_entry **link_p;
    struct exclude_entry * next_p;

    if (_wfopen_s(&stream_p, path, L"r, ccs=UTF-8")) {
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
		if (next_p == NULL){
			report_error(L"HeapAlloc failed to allocate memory", GetLastError());
			ExitProcess(203);
			}
        // read in the path to watch from config.txt
        get_result = \
            fgetws(full_file_name, ARRAYSIZE(full_file_name), stream_p);

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
        line_len = wcslen(full_file_name);
		if (line_len && full_file_name[line_len-1] == L'\n'){
			full_file_name[line_len-1] = L'\0';
			line_len--;
			}
        if (full_file_name[0] == L'\0')
           continue;
		next_p->dir_path_len = line_len;
		next_p->dir_path = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
			(line_len + 1) * sizeof(wchar_t));
		if (next_p->dir_path == NULL){
			report_error(L"HeapAlloc failed to allocate memory", GetLastError());
			ExitProcess(204);
		}
		wcsncpy_s(next_p->dir_path, line_len+1, full_file_name, line_len);
   
        // add this entry to the list
        *link_p = next_p;

        // point to the new entry's next pointer 
        link_p = &(*link_p)->next_p;
    } // while(1)

    fclose(stream_p);

} // load_paths_to_exclude

//------------------------------------------------------------------------------
static BOOL parent_is_gone(HANDLE hParent) {
//------------------------------------------------------------------------------
	DWORD exit_code;
	if (hParent == NULL)
		return FALSE;
	if (!GetExitCodeProcess(hParent, &exit_code) ||
		exit_code != STILL_ACTIVE)
		return TRUE;
	return FALSE;

} // static BOOL parent_is_gone(DWORD parent_pid) {


void write_path_to_temp_file(wchar_t *path, size_t buffer_size, HANDLE *phChangeLog){
	errno_t copy_result;
	DWORD converted_chars, bytes_written;

	copy_result = wcscat_s(path, buffer_size, L"\n");
	if (copy_result != 0){
		report_error(L"wcscat_s", copy_result);
		ExitProcess(27);
		}

	converted_chars = WideCharToMultiByte(
		CP_UTF8, 
		0,
		path,
		-1,
		mbcs_buffer,
		sizeof(mbcs_buffer),
		NULL,
		NULL
		);
	if (converted_chars == 0) {
		report_error(L"WideCharToMultiByte", GetLastError());
		ExitProcess(20);
		}

	if (INVALID_HANDLE_VALUE == *phChangeLog) {
		// open the change log file
		*phChangeLog = CreateFile(
			temp_file_path,           // LPCTSTR lpFileName,
			GENERIC_WRITE,            // DWORD dwDesiredAccess,
			0,                        // DWORD dwShareMode,
			NULL,                     // LPSECURITY_ATTRIBUTES
			CREATE_ALWAYS,            // DWORD dwCreationDisposition,
			FILE_ATTRIBUTE_NORMAL,    // DWORD dwFlagsAndAttributes,
			NULL                      // HANDLE hTemplateFile
		);

		if (INVALID_HANDLE_VALUE == *phChangeLog) {
			report_error(L"CreateFile temp changelog", GetLastError());
			ExitProcess(21);
		}
	}

	if (!WriteFile(
			*phChangeLog,             // HANDLE hFile,
			mbcs_buffer,            // LPCVOID lpBuffer,
			converted_chars-1,      // DWORD nNumberOfBytesToWrite,
			&bytes_written,         // LPDWORD lpNumberOfBytesWritten,
			NULL)){
		report_error(L"WriteFile temp changelog", GetLastError());
		ExitProcess(22);
	}
}

//-----------------------------------------------------------------------------
static void process_dir_watcher_results(
    watch_entry *watch_entry_p,
	DWORD           buffer_size){
//-----------------------------------------------------------------------------
    HANDLE hChangeLog;
    PFILE_NOTIFY_INFORMATION buffer_p;
    DWORD buffer_index;
    BOOL more;
    SSIZE_T path_len;
    int compare_result;
    BOOL exclude;
    struct exclude_entry * exclude_entry_p;
    DWORD error_code;
	errno_t copy_result;
	LPWSTR fmt, slash_pos;

	hChangeLog = INVALID_HANDLE_VALUE;
    more = TRUE;
    buffer_index = 0;

	// If buffer size is 0, indicates that too many changes occurred to fit in the buffer
	// Write out the top level dir to trigger the monitor to do a full pass of it
	if (buffer_size == 0){
		more = FALSE;
		copy_result = wcsncpy_s(full_file_name, ARRAYSIZE(full_file_name),
			watch_entry_p->dir_path, watch_entry_p->dir_path_len);
		if (copy_result != 0){
			report_error(L"wcsncpy_s failed", copy_result);
			ExitProcess(28);
			}
		write_path_to_temp_file(full_file_name, ARRAYSIZE(full_file_name), &hChangeLog);
	}

	while (more) {
		buffer_p = (PFILE_NOTIFY_INFORMATION) &watch_entry_p->changes_buffer[buffer_index];
		// Cannot use just sizeof(FILE_NOTIFY_INFORMATION) as it includes 2 bytes of struct padding,
		// causing this check to fail for single-character filenames
		size_t entry_size = offsetof(FILE_NOTIFY_INFORMATION, FileName) + buffer_p->FileNameLength;
        if ((buffer_index + entry_size) > buffer_size) {
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

        copy_result = wcsncpy_s(relative_file_name, ARRAYSIZE(relative_file_name),
			buffer_p->FileName, buffer_p->FileNameLength/sizeof(wchar_t));
		if (copy_result != 0){
			report_error(L"wcsncpy_s failed", copy_result);
			ExitProcess(25);
			}

        // 2010-09-05 dougfort -- if the dir_path ends in a slash 
        // (probably something like c:\) then we don't want to
        // interpolate another slash
		if (watch_entry_p->dir_path[watch_entry_p->dir_path_len-1] == L'\\')
			fmt = L"%s%s";
		else
			fmt = L"%s\\%s";
		path_len = _snwprintf_s(full_file_name, ARRAYSIZE(full_file_name), _TRUNCATE,
			fmt, watch_entry_p->dir_path, relative_file_name);
		if (path_len == -1){
			report_error(L"_snwprintf_s failed, path too long",
				(DWORD)(watch_entry_p->dir_path_len + wcslen(relative_file_name)));
			ExitProcess(26);
		}

		// We want the directory where the event took place, 
		// for consistency with OSX.
		// Needs to be done before calling GetLongPathName since in the case of
		// a rename or delete the actual file itself is already gone
		if (full_file_name[path_len-1] != L'\\') {
			slash_pos = wcsrchr(full_file_name, L'\\');
			if (slash_pos)
				*slash_pos = L'\0';
		}

		// Need to translate short names before checking excludes
		// According to MSDN docs, you can reuse the same buffer for output
		path_len = GetLongPathNameW(
			full_file_name,
			full_file_name,
			ARRAYSIZE(full_file_name)
		);
		// Note that most of errors that occurred here were due to a buffer overflow
		// which has since been fixed.  In case of error, pass orig filename unchanged and
		// let code that picks up output deal with removed folders, etc
		if (path_len == 0) {
			error_code = GetLastError();
			report_error(L"GetLongPathNameW", error_code);
			path_len=wcslen(full_file_name);
		}
		else if (path_len > ARRAYSIZE(full_file_name)){
			// Shouldn't happen since buffer is maximum possible path length
			report_error(L"GetLongPathNameW result would overflow buffer", (DWORD)path_len);
			ExitProcess(27);
		}

		// Can check for excludes last since we only ever exclude folders
        exclude = FALSE;
        for (
            exclude_entry_p=exclude_entry_list_p; 
            exclude_entry_p != NULL; 
            exclude_entry_p = exclude_entry_p->next_p
        ) {
            compare_result = _wcsnicmp(
                full_file_name,
                exclude_entry_p->dir_path,
                exclude_entry_p->dir_path_len
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

		write_path_to_temp_file(full_file_name, ARRAYSIZE(full_file_name), &hChangeLog);

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

    int num_args;
    int parent_pid;
    HANDLE hParent;
    HANDLE completion_port_h;
    LPWSTR * args_p;
    BOOL get_successful;
    DWORD bytes_returned;
    struct watch_entry * watch_entry_p;
    ULONG_PTR completion_key;
    int loop_count;

	/* Python's subprocess doesn't use the widechar API (CreateProcessW) in Python 2.x.
		In order to support non-ascii characters, the command line is encoded in utf-8
		and decoded manually here.
	*/
	int required_len;
	WCHAR *command_line;
	LPSTR utf8_command_line = GetCommandLineA();
	required_len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8_command_line, -1, NULL, 0);
	if (required_len == 0)
		return GetLastError();
	command_line = (WCHAR *)malloc(required_len * sizeof(WCHAR));
	if (command_line == NULL)
		return ERROR_OUTOFMEMORY;
	required_len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8_command_line, -1, command_line, required_len);
	if (required_len == 0)
		return GetLastError();
	args_p = CommandLineToArgvW(command_line, &num_args);
	if (args_p == NULL)
		return GetLastError();

    if (num_args != 5) {
        return 1;
    }
    notification_path = args_p[4];
    wsprintf(error_path, L"%s\\error.txt", notification_path);
    wsprintf(temp_file_path, L"%s\\temp", notification_path);
    memset(error_buffer, '\0', sizeof(error_buffer));

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

	parent_pid = _wtoi(args_p[1]);
	// Use 0 for debugging
	if (parent_pid == 0)
		hParent = NULL;
	else{
		hParent = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, parent_pid);
		if (hParent == NULL){
			report_error(L"OpenProcess", GetLastError());
			ExitProcess(105);
		}
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
                if (parent_is_gone(hParent)) {
                    break;
                } else {
                    continue;
                }
            }
            report_error(L"GetQueuedCompletionStatus", GetLastError());
            ExitProcess(115);
        }

        process_dir_watcher_results(watch_entry_p, bytes_returned);
        // start a new watch
        start_watch(watch_entry_p);

        if (loop_count % PARENT_CHECK_COUNT == 0) {
             if (parent_is_gone(hParent)) {
                 break;
             }
        }

    } // while (TRUE) {

    // We get here if we think the parent is gone
    return 0;

} // _tWinMain
