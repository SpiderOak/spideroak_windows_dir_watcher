# You may need to run vsvars32.bat if you don't normally run from the commandline
#"E:\Program Files\Microsoft Visual Studio 8\Common7\Tools\vsvars32.bat"
cl /MT /D "WIN32" /D "_UNICODE" /D "UNICODE" /SYSTEM:WINDOWS spideroak_windows_dir_watcher.cpp psapi.lib  kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib

