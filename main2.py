import ctypes
import ctypes.wintypes as wintypes
import sys
import time
import json
import os
import threading
from tkinter import *
from tkinter import ttk, scrolledtext, messagebox
import tkinter as tk
from colorama import Fore, init

init()

print("Made by Nixtera. Enjoy.")

class NOPDumpGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NOPDump v0.1")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # Переменные
        self.is_scanning = False
        self.scan_thread = None
        
        self.setup_ui()
        
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(N, W, E, S))
        
        # Title
        title_label = ttk.Label(main_frame, text="NOPDump", font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 10))
        
        # Status frame
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding="5")
        status_frame.grid(row=1, column=0, columnspan=2, sticky=(W, E), pady=(0, 10))
        
        self.status_label = ttk.Label(status_frame, text="Ready to scan")
        self.status_label.grid(row=0, column=0, sticky=W)
        
        self.progress = ttk.Progressbar(status_frame, mode='indeterminate')
        self.progress.grid(row=0, column=1, sticky=(W, E), padx=(10, 0))
        
        # Info frame
        info_frame = ttk.LabelFrame(main_frame, text="Process Information", padding="5")
        info_frame.grid(row=2, column=0, columnspan=2, sticky=(W, E), pady=(0, 10))
        
        ttk.Label(info_frame, text="PID:").grid(row=0, column=0, sticky=W)
        self.pid_label = ttk.Label(info_frame, text="Not found")
        self.pid_label.grid(row=0, column=1, sticky=W, padx=(5, 0))
        
        ttk.Label(info_frame, text="Base Address:").grid(row=1, column=0, sticky=W)
        self.base_label = ttk.Label(info_frame, text="0x0000000000000000")
        self.base_label.grid(row=1, column=1, sticky=W, padx=(5, 0))
        
        ttk.Label(info_frame, text="Module Size:").grid(row=2, column=0, sticky=W)
        self.size_label = ttk.Label(info_frame, text="0x0 bytes")
        self.size_label.grid(row=2, column=1, sticky=W, padx=(5, 0))
        
        # Console output
        console_frame = ttk.LabelFrame(main_frame, text="Console Output", padding="5")
        console_frame.grid(row=3, column=0, columnspan=2, sticky=(W, E, N, S), pady=(0, 10))
        
        self.console = scrolledtext.ScrolledText(console_frame, height=15, width=70)
        self.console.grid(row=0, column=0, sticky=(W, E, N, S))
        
        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=4, column=0, columnspan=2, pady=(0, 10))
        
        self.scan_button = ttk.Button(buttons_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=0, padx=(0, 5))
        
        self.stop_button = ttk.Button(buttons_frame, text="Stop Scan", command=self.stop_scan, state=DISABLED)
        self.stop_button.grid(row=0, column=1, padx=(5, 0))
        
        self.export_button = ttk.Button(buttons_frame, text="Export Offsets", command=self.export_offsets, state=DISABLED)
        self.export_button.grid(row=0, column=2, padx=(5, 0))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)
        console_frame.columnconfigure(0, weight=1)
        console_frame.rowconfigure(0, weight=1)
        status_frame.columnconfigure(1, weight=1)
        
        # Redirect stdout to console
        self.old_stdout = sys.stdout
        sys.stdout = TextRedirector(self.console, "stdout")
        
        # Load patterns
        self.patterns = self.load_patterns()
        
    def load_patterns(self):
        try:
            with open("patterns.json", "r") as f:
                return json.load(f)
        except FileNotFoundError:
            self.log_error("patterns.json not found!")
            return []
        except json.JSONDecodeError:
            self.log_error("Invalid JSON in patterns.json!")
            return []
    
    def log_error(self, message):
        self.console.insert(END, f"[ERROR] {message}\n")
        self.console.see(END)
    
    def start_scan(self):
        if self.is_scanning:
            return
            
        self.is_scanning = True
        self.scan_button.config(state=DISABLED)
        self.stop_button.config(state=NORMAL)
        self.export_button.config(state=DISABLED)
        self.progress.start()
        
        self.scan_thread = threading.Thread(target=self.scan_process)
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def stop_scan(self):
        if self.is_scanning:
            self.is_scanning = False
            self.scan_button.config(state=NORMAL)
            self.stop_button.config(state=DISABLED)
            self.progress.stop()
    
    def export_offsets(self):
        # This would export the found offsets
        messagebox.showinfo("Export", "Offsets exported to offsets.txt")
    
    def scan_process(self):
        try:
            self.update_status("Finding Roblox process...")
            target_process = "RobloxPlayerBeta.exe"
            pid = get_pid(target_process)
            
            if not pid:
                self.update_status("Roblox process not found")
                self.log_error("Roblox process not found.")
                self.stop_scan()
                return
                
            self.update_gui(lambda: self.pid_label.config(text=str(pid)))
            self.log_info(f"Roblox PID: {pid}")
            
            base, size = get_module_info(pid, target_process)
            if not base or not size:
                self.update_status("Failed to get module info")
                self.log_error("Failed to get module info.")
                self.stop_scan()
                return
                
            self.update_gui(lambda: self.base_label.config(text=f"0x{base:016X}"))
            self.update_gui(lambda: self.size_label.config(text=f"0x{size:X} bytes"))
            print("Module Base Address founded. Check NOPDump")
            self.log_info(f"Module Base Address: 0x{base:016X}")
            self.log_info(f"Module Size: 0x{size:X} bytes")
            
            h_process = op(pid)
            if not h_process:
                self.update_status("Failed to open process")
                self.log_error("Failed to open Roblox process.")
                self.stop_scan()
                return
                
            self.update_status("Scanning memory...")
            found_offsets = self.scan_memory(h_process, base, size)
            
            close_handle(h_process)
            
            if found_offsets:
                with open("offsets.txt", "w") as f:
                    for name, offset in found_offsets.items():
                        f.write(f"{name} = 0x{offset:X}\n")
                self.log_info("Offsets saved to offsets.txt")
                self.update_gui(lambda: self.export_button.config(state=NORMAL))
            else:
                self.log_info("No patterns found.")
                
            self.update_status("Scan completed")
            
        except Exception as e:
            self.log_error(f"Scan error: {str(e)}")
            self.update_status("Scan failed")
        finally:
            self.stop_scan()
    
    def scan_memory(self, h_process, base, size):
        start = base
        end = base + size
        found_offsets = {}
        current = start
        
        while current < end and self.is_scanning:
            mbi = virtual_query_ex(h_process, current)
            if not mbi:
                break
                
            if (mbi.State == MEM_COMMIT and
                not (mbi.Protect & PAGE_GUARD) and
                not (mbi.Protect & PAGE_NOACCESS) and
                mbi.BaseAddress >= start and mbi.BaseAddress < end):
                
                region_start = mbi.BaseAddress
                region_size = mbi.RegionSize
                if region_start + region_size > end:
                    region_size = end - region_start
                
                for pattern_str, name in self.patterns:
                    if not self.is_scanning:
                        break
                        
                    pattern_bytes, mask = pattern_to_bytes(pattern_str)
                    if pattern_bytes is None:
                        continue
                        
                    found = scan_region(h_process, region_start, region_size, pattern_bytes, mask)
                    if found:
                        offset = found - base
                        found_offsets[name] = offset
                        self.log_info(f"{name:15} -> Address: 0x{found:016X} | Offset: 0x{offset:X}")
            
            current = mbi.BaseAddress + mbi.RegionSize
        
        return found_offsets
    
    def update_status(self, message):
        self.update_gui(lambda: self.status_label.config(text=message))
    
    def log_info(self, message):
        self.console.insert(END, f"[INFO] {message}\n")
        self.console.see(END)
    
    def update_gui(self, func):
        self.root.after(0, func)

class TextRedirector:
    def __init__(self, widget, tag="stdout"):
        self.widget = widget
        self.tag = tag
    
    def write(self, string):
        self.widget.insert(END, string)
        self.widget.see(END)
    
    def flush(self):
        pass

# Ваши оригинальные функции (оставлены без изменений)

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('cntUsage', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('th32DefaultHeapID', ctypes.POINTER(wintypes.ULONG)),
        ('th32ModuleID', wintypes.DWORD),
        ('cntThreads', wintypes.DWORD),
        ('th32ParentProcessID', wintypes.DWORD),
        ('pcPriClassBase', wintypes.LONG),
        ('dwFlags', wintypes.DWORD),
        ('szExeFile', wintypes.CHAR * 260),
    ]

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('th32ModuleID', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('GlblcntUsage', wintypes.DWORD),
        ('ProccntUsage', wintypes.DWORD),
        ('modBaseAddr', ctypes.POINTER(ctypes.c_byte)),
        ('modBaseSize', wintypes.DWORD),
        ('hModule', wintypes.HMODULE),
        ('szModule', wintypes.CHAR * 256),
        ('szExePath', wintypes.CHAR * wintypes.MAX_PATH)
    ]

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_void_p),
        ("AllocationBase",    ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize",        ctypes.c_size_t),
        ("State",             wintypes.DWORD),
        ("Protect",           wintypes.DWORD),
        ("Type",              wintypes.DWORD),
    ]

def get_pid(process_name):
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == wintypes.HANDLE(-1).value:
        return 0
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    if not kernel32.Process32First(snapshot, ctypes.byref(entry)):
        kernel32.CloseHandle(snapshot)
        return 0
    while True:
        exe_name = entry.szExeFile.decode(errors='ignore')
        if exe_name.lower() == process_name.lower():
            pid = entry.th32ProcessID
            kernel32.CloseHandle(snapshot)
            return pid
        if not kernel32.Process32Next(snapshot, ctypes.byref(entry)):
            break
    kernel32.CloseHandle(snapshot)
    return 0

def get_module_info(pid, module_name):
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snapshot == wintypes.HANDLE(-1).value:
        return 0, 0
    module_entry = MODULEENTRY32()
    module_entry.dwSize = ctypes.sizeof(MODULEENTRY32)
    if not kernel32.Module32First(snapshot, ctypes.byref(module_entry)):
        kernel32.CloseHandle(snapshot)
        return 0, 0
    while True:
        mod_name = module_entry.szModule.decode(errors='ignore')
        if mod_name.lower() == module_name.lower():
            base = ctypes.cast(module_entry.modBaseAddr, ctypes.c_void_p).value
            size = module_entry.modBaseSize
            kernel32.CloseHandle(snapshot)
            return base, size
        if not kernel32.Module32Next(snapshot, ctypes.byref(module_entry)):
            break
    kernel32.CloseHandle(snapshot)
    return 0, 0

def pattern_to_bytes(pattern):
    bytes_arr = []
    mask = ""
    i = 0
    length = len(pattern)
    while i < length:
        if pattern[i] == ' ':
            i += 1
            continue
        if pattern[i] == '?':
            bytes_arr.append(0)
            mask += '?'
            i += 1
            if i < length and pattern[i] == '?':
                i += 1
        else:
            if i + 1 >= length:
                return None, None
            def hex_char_to_int(c):
                if '0' <= c <= '9': return ord(c) - ord('0')
                if 'a' <= c <= 'f': return ord(c) - ord('a') + 10
                if 'A' <= c <= 'F': return ord(c) - ord('A') + 10
                return -1
            high = hex_char_to_int(pattern[i])
            low = hex_char_to_int(pattern[i+1])
            if high == -1 or low == -1:
                return None, None
            bytes_arr.append((high << 4) | low)
            mask += 'x'
            i += 2
    return bytes_arr, mask

def dc(data, pattern, mask):
    for i in range(len(pattern)):
        if mask[i] == 'x' and data[i] != pattern[i]:
            return False
    return True

def scan_region(h_process, base, size, pattern, mask):
    ReadProcessMemory = kernel32.ReadProcessMemory
    ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    ReadProcessMemory.restype = wintypes.BOOL
    buffer = (ctypes.c_ubyte * size)()
    bytes_read = ctypes.c_size_t(0)
    if not ReadProcessMemory(h_process, ctypes.c_void_p(base), buffer, size, ctypes.byref(bytes_read)):
        return 0
    if bytes_read.value < len(pattern):
        return 0
    data = bytearray(buffer)[:bytes_read.value]
    plen = len(pattern)
    for i in range(bytes_read.value - plen + 1):
        if dc(data[i:i+plen], pattern, mask):
            return base + i
    return 0

def virtual_query_ex(h_process, address):
    mbi = MEMORY_BASIC_INFORMATION()
    result = kernel32.VirtualQueryEx(h_process, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
    if result != ctypes.sizeof(mbi):
        return None
    return mbi

def op(pid):
    return kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)

def close_handle(handle):
    kernel32.CloseHandle(handle)

def main():
    root = tk.Tk()
    app = NOPDumpGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
