cl /GL /D WIN32 /D NDEBUG /D _WINDOWS /D _UNICODE /D UNICODE /FD /MD /W3 /Wp64 /Zi /TC spideroak_windows_dir_watcher.cpp /c

link /OUT:spideroak_windows_dir_watcher.exe /INCREMENTAL:NO /MANIFEST /MANIFESTFILE:spideroak_windows_dir_watcher.exe.intermediate.manifest /MANIFESTUAC:"level='asInvoker' uiAccess='false'" /SUBSYSTEM:WINDOWS /OPT:REF /OPT:ICF /LTCG /DYNAMICBASE:NO /MACHINE:X86 psapi.lib kernel32.lib user32.lib advapi32.lib shell32.lib uuid.lib spideroak_windows_dir_watcher.obj

mt /outputresource:"spideroak_windows_dir_watcher.exe;#1" /manifest spideroak_windows_dir_watcher.exe.intermediate.manifest
