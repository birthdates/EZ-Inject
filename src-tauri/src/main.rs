#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use base64::{engine::general_purpose, Engine as _};
use image::{codecs::png::PngEncoder, ColorType, ImageEncoder, RgbaImage};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    ffi::c_void,
    fs,
    mem::{size_of, transmute},
    path::PathBuf,
    ptr::null_mut,
    slice,
};
use tauri::{AppHandle, Manager, Window};
use windows::{
    core::{s, PCWSTR, PWSTR},
    Win32::{
        Foundation::{
            CloseHandle, BOOL, FILETIME, HANDLE, HMODULE, HWND, LPARAM, WAIT_FAILED, WAIT_OBJECT_0,
            WAIT_TIMEOUT,
        },
        Graphics::Gdi::{
            CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject, SelectObject, BITMAPINFO,
            BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, HGDIOBJ,
        },
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
            LibraryLoader::{GetModuleHandleW, GetProcAddress},
            Memory::{
                VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
            },
            RemoteDesktop::ProcessIdToSessionId,
            Threading::{
                CreateRemoteThread, GetCurrentProcessId, GetExitCodeThread, GetProcessTimes,
                OpenProcess, WaitForSingleObject, LPTHREAD_START_ROUTINE, PROCESS_CREATE_THREAD,
                PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
            },
        },
        UI::{
            Shell::{SHGetFileInfoW, SHFILEINFOW, SHGFI_ICON, SHGFI_SMALLICON},
            WindowsAndMessaging::{
                DestroyIcon, DrawIconEx, EnumWindows, GetWindowThreadProcessId, IsWindowVisible,
                DI_NORMAL,
            },
        },
    },
};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProcessEntry {
    pid: u32,
    process_name: String,
    exe_name: String,
    exe_path: Option<String>,
    icon_data_url: Option<String>,
    created_at_ms: Option<u64>,
    is_user_process: bool,
    has_window: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DllEntry {
    path: String,
    enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SelectedTarget {
    mode: String,
    value: String,
    label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Profile {
    id: String,
    name: String,
    selected_target: Option<SelectedTarget>,
    dlls: Vec<DllEntry>,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            id: "main".to_string(),
            name: "Main".to_string(),
            selected_target: None,
            dlls: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct AppSettings {
    refresh_interval_ms: u64,
    process_sort: String,
    process_filter: String,
    success_popup_enabled: bool,
    success_popup_duration_ms: u64,
    confetti_enabled: bool,
    shake_enabled: bool,
    dont_show_success_again: bool,
    active_profile_id: String,
    profiles: Vec<Profile>,
    #[serde(skip_serializing)]
    selected_target: Option<SelectedTarget>,
    #[serde(skip_serializing)]
    dlls: Vec<DllEntry>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            refresh_interval_ms: 5_000,
            process_sort: "created".to_string(),
            process_filter: "all".to_string(),
            success_popup_enabled: true,
            success_popup_duration_ms: 5_000,
            confetti_enabled: true,
            shake_enabled: true,
            dont_show_success_again: false,
            active_profile_id: "main".to_string(),
            profiles: vec![Profile::default()],
            selected_target: None,
            dlls: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct InjectionResult {
    dll_path: String,
    success: bool,
    message: String,
}

const LOAD_LIBRARY_WAIT_TIMEOUT_MS: u32 = 15_000;

#[tauri::command]
fn list_processes() -> Result<Vec<ProcessEntry>, String> {
    enumerate_processes()
}

#[tauri::command]
fn pick_dlls() -> Result<Vec<String>, String> {
    let files = rfd::FileDialog::new()
        .set_title("Select DLLs")
        .add_filter("Dynamic Link Library", &["dll"])
        .pick_files()
        .unwrap_or_default();

    Ok(files
        .into_iter()
        .map(|path| path.to_string_lossy().to_string())
        .collect())
}

#[tauri::command]
fn load_settings(app: AppHandle) -> Result<AppSettings, String> {
    let path = settings_path(&app)?;
    if !path.exists() {
        return Ok(AppSettings::default());
    }

    let content = fs::read_to_string(path).map_err(|error| error.to_string())?;
    let mut settings: AppSettings = serde_json::from_str(&content).unwrap_or_default();
    normalize_settings(&mut settings);
    Ok(settings)
}

#[tauri::command]
fn save_settings(app: AppHandle, mut settings: AppSettings) -> Result<(), String> {
    normalize_settings(&mut settings);
    let path = settings_path(&app)?;
    let content = serde_json::to_string_pretty(&settings).map_err(|error| error.to_string())?;
    fs::write(path, content).map_err(|error| error.to_string())
}

#[tauri::command]
fn inject_dlls(
    target: SelectedTarget,
    dlls: Vec<DllEntry>,
) -> Result<Vec<InjectionResult>, String> {
    let processes = enumerate_processes()?;
    let pid = resolve_target_pid(&target, &processes)?;

    let mut results = Vec::new();
    for dll in dlls.into_iter().filter(|dll| dll.enabled) {
        if !dll.path.to_ascii_lowercase().ends_with(".dll") {
            results.push(InjectionResult {
                dll_path: dll.path,
                success: false,
                message: "Skipped because the file is not a DLL path.".to_string(),
            });
            continue;
        }

        let path = PathBuf::from(&dll.path);
        if !path.exists() {
            results.push(InjectionResult {
                dll_path: dll.path,
                success: false,
                message: "DLL path does not exist.".to_string(),
            });
            continue;
        }

        let dll_path = dll.path.clone();
        match inject_one(pid, &dll_path) {
            Ok(()) => results.push(InjectionResult {
                dll_path,
                success: true,
                message: "Loaded with LoadLibraryW.".to_string(),
            }),
            Err(error) => results.push(InjectionResult {
                dll_path,
                success: false,
                message: error,
            }),
        }
    }

    Ok(results)
}

#[tauri::command]
fn window_minimize(window: Window) -> Result<(), String> {
    window.minimize().map_err(|error| error.to_string())
}

#[tauri::command]
fn window_toggle_maximize(window: Window) -> Result<(), String> {
    let is_maximized = window.is_maximized().map_err(|error| error.to_string())?;
    if is_maximized {
        window.unmaximize().map_err(|error| error.to_string())
    } else {
        window.maximize().map_err(|error| error.to_string())
    }
}

#[tauri::command]
fn window_close(window: Window) -> Result<(), String> {
    window.close().map_err(|error| error.to_string())
}

#[tauri::command]
fn start_window_drag(window: Window) -> Result<(), String> {
    window.start_dragging().map_err(|error| error.to_string())
}

fn settings_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|error| error.to_string())?;
    fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
    Ok(dir.join("settings.json"))
}

fn normalize_settings(settings: &mut AppSettings) {
    settings.refresh_interval_ms = settings.refresh_interval_ms.clamp(1_000, 15_000);
    settings.success_popup_duration_ms = settings.success_popup_duration_ms.clamp(1_500, 10_000);
    if settings.process_sort != "created" && settings.process_sort != "az" {
        settings.process_sort = "created".to_string();
    }
    if !matches!(
        settings.process_filter.as_str(),
        "all" | "user" | "window" | "selected"
    ) {
        settings.process_filter = "all".to_string();
    }

    let has_legacy_profile_data = settings.selected_target.is_some() || !settings.dlls.is_empty();
    let only_empty_default_profile = settings.profiles.len() == 1
        && settings.profiles[0].id == "main"
        && settings.profiles[0].selected_target.is_none()
        && settings.profiles[0].dlls.is_empty();

    if settings.profiles.is_empty() || (has_legacy_profile_data && only_empty_default_profile) {
        settings.profiles = vec![Profile {
            id: "main".to_string(),
            name: "Main".to_string(),
            selected_target: settings.selected_target.clone(),
            dlls: settings.dlls.clone(),
        }];
    }

    let mut seen_ids = HashSet::new();
    for (index, profile) in settings.profiles.iter_mut().enumerate() {
        if profile.id.trim().is_empty() || seen_ids.contains(&profile.id) {
            profile.id = if index == 0 {
                "main".to_string()
            } else {
                format!("profile-{index}")
            };
        }
        seen_ids.insert(profile.id.clone());

        if profile.name.trim().is_empty() {
            profile.name = if index == 0 {
                "Main".to_string()
            } else {
                format!("Profile {index}")
            };
        }
    }

    if !settings
        .profiles
        .iter()
        .any(|profile| profile.id == settings.active_profile_id)
    {
        settings.active_profile_id = settings
            .profiles
            .first()
            .map(|profile| profile.id.clone())
            .unwrap_or_else(|| "main".to_string());
    }
}

fn enumerate_processes() -> Result<Vec<ProcessEntry>, String> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|error| error.to_string())?;
    let current_session = process_session_id(unsafe { GetCurrentProcessId() });
    let window_pids = visible_window_pids();

    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut processes = Vec::new();

    let mut has_entry = unsafe { Process32FirstW(snapshot, &mut entry).is_ok() };
    while has_entry {
        let pid = entry.th32ProcessID;
        let exe_name = wide_fixed_to_string(&entry.szExeFile);
        let exe_path = query_process_path(pid);
        let process_name = if exe_name.is_empty() {
            format!("PID {pid}")
        } else {
            exe_name.clone()
        };
        let icon_data_url = exe_path
            .as_deref()
            .and_then(extract_icon_data_url)
            .or_else(|| exe_path.as_deref().and_then(extract_icon_data_url));

        processes.push(ProcessEntry {
            pid,
            process_name,
            exe_name,
            exe_path,
            icon_data_url,
            created_at_ms: query_process_creation_ms(pid),
            is_user_process: current_session
                .zip(process_session_id(pid))
                .map(|(current, process)| current == process)
                .unwrap_or(false),
            has_window: window_pids.contains(&pid),
        });

        has_entry = unsafe { Process32NextW(snapshot, &mut entry).is_ok() };
    }

    unsafe {
        let _ = CloseHandle(snapshot);
    }

    Ok(processes)
}

fn resolve_target_pid(target: &SelectedTarget, processes: &[ProcessEntry]) -> Result<u32, String> {
    let value = target.value.trim();
    if value.is_empty() {
        return Err("No target value was saved.".to_string());
    }

    let found = match target.mode.as_str() {
        "pid" => value
            .parse::<u32>()
            .ok()
            .and_then(|pid| processes.iter().find(|process| process.pid == pid)),
        "exePath" => {
            let value_lower = value.to_ascii_lowercase();
            processes.iter().find(|process| {
                process
                    .exe_path
                    .as_ref()
                    .map(|path| path.to_ascii_lowercase() == value_lower)
                    .unwrap_or(false)
                    || process.exe_name.to_ascii_lowercase() == value_lower
            })
        }
        "processName" => {
            let value_lower = value.to_ascii_lowercase();
            processes
                .iter()
                .find(|process| process.process_name.to_ascii_lowercase() == value_lower)
        }
        _ => None,
    };

    found.map(|process| process.pid).ok_or_else(|| {
        format!(
            "Target is not running or cannot be resolved: {}",
            target.label
        )
    })
}

fn inject_one(pid: u32, dll_path: &str) -> Result<(), String> {
    let process = unsafe {
        OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_QUERY_LIMITED_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ,
            false,
            pid,
        )
    }
    .map_err(|error| format!("OpenProcess failed: {error}"))?;

    let wide_path = to_wide_null(dll_path);
    let byte_len = wide_path.len() * size_of::<u16>();
    let remote_mem = unsafe {
        VirtualAllocEx(
            process,
            None,
            byte_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if remote_mem.is_null() {
        unsafe {
            let _ = CloseHandle(process);
        }
        return Err("VirtualAllocEx failed.".to_string());
    }

    let mut written = 0usize;
    let wrote = unsafe {
        WriteProcessMemory(
            process,
            remote_mem,
            wide_path.as_ptr() as *const c_void,
            byte_len,
            Some(&mut written),
        )
        .is_ok()
    };

    if !wrote || written != byte_len {
        cleanup_remote(process, remote_mem);
        return Err("WriteProcessMemory failed.".to_string());
    }

    let kernel32: HMODULE = unsafe { GetModuleHandleW(windows::core::w!("kernel32.dll")) }
        .map_err(|error| {
            cleanup_remote(process, remote_mem);
            format!("GetModuleHandleW(kernel32.dll) failed: {error}")
        })?;
    let load_library =
        unsafe { GetProcAddress(kernel32, s!("LoadLibraryW")) }.ok_or_else(|| {
            cleanup_remote(process, remote_mem);
            "GetProcAddress(LoadLibraryW) failed.".to_string()
        })?;
    let start_routine: LPTHREAD_START_ROUTINE = unsafe { transmute(load_library) };

    let thread =
        unsafe { CreateRemoteThread(process, None, 0, start_routine, Some(remote_mem), 0, None) }
            .map_err(|error| {
            cleanup_remote(process, remote_mem);
            format!("CreateRemoteThread failed: {error}")
        })?;

    let wait_result = unsafe { WaitForSingleObject(thread, LOAD_LIBRARY_WAIT_TIMEOUT_MS) };
    if wait_result == WAIT_TIMEOUT {
        close_unfinished_remote_thread(process, thread);
        return Err(format!(
            "LoadLibraryW did not finish within {} seconds. The remote thread was left running to avoid corrupting the target process.",
            LOAD_LIBRARY_WAIT_TIMEOUT_MS / 1_000
        ));
    }
    if wait_result == WAIT_FAILED {
        close_unfinished_remote_thread(process, thread);
        return Err("WaitForSingleObject failed while waiting for LoadLibraryW.".to_string());
    }
    if wait_result != WAIT_OBJECT_0 {
        close_unfinished_remote_thread(process, thread);
        return Err(format!(
            "Unexpected WaitForSingleObject result while waiting for LoadLibraryW: {}.",
            wait_result.0
        ));
    }

    let mut exit_code = 0;
    let got_exit_code = unsafe { GetExitCodeThread(thread, &mut exit_code).is_ok() };
    unsafe {
        let _ = CloseHandle(thread);
    }
    cleanup_remote(process, remote_mem);

    if !got_exit_code {
        return Err("GetExitCodeThread failed.".to_string());
    }
    if exit_code == 0 {
        return Err("LoadLibraryW returned NULL inside the target process.".to_string());
    }

    Ok(())
}

fn close_unfinished_remote_thread(process: HANDLE, thread: HANDLE) {
    unsafe {
        let _ = CloseHandle(thread);
        let _ = CloseHandle(process);
    }
}

fn cleanup_remote(process: HANDLE, remote_mem: *mut c_void) {
    unsafe {
        if !remote_mem.is_null() {
            let _ = VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
        }
        let _ = CloseHandle(process);
    }
}

fn query_process_path(pid: u32) -> Option<String> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut buffer = vec![0u16; 32_768];
    let mut size = buffer.len() as u32;
    let success = unsafe {
        windows::Win32::System::Threading::QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut size,
        )
        .is_ok()
    };
    unsafe {
        let _ = CloseHandle(process);
    }

    if success && size > 0 {
        Some(String::from_utf16_lossy(&buffer[..size as usize]))
    } else {
        None
    }
}

fn query_process_creation_ms(pid: u32) -> Option<u64> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let success = unsafe {
        GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user).is_ok()
    };
    unsafe {
        let _ = CloseHandle(process);
    }

    if !success {
        return None;
    }

    let ticks = ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64;
    const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
    ticks
        .checked_sub(WINDOWS_TO_UNIX_EPOCH_100NS)
        .map(|unix_100ns| unix_100ns / 10_000)
}

fn process_session_id(pid: u32) -> Option<u32> {
    let mut session_id = 0;
    let success = unsafe { ProcessIdToSessionId(pid, &mut session_id).is_ok() };
    if success {
        Some(session_id)
    } else {
        None
    }
}

fn visible_window_pids() -> HashSet<u32> {
    unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let pids = &mut *(lparam.0 as *mut HashSet<u32>);
        if IsWindowVisible(hwnd).as_bool() {
            let mut pid = 0;
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
            if pid != 0 {
                pids.insert(pid);
            }
        }
        BOOL(1)
    }

    let mut pids = HashSet::new();
    unsafe {
        let _ = EnumWindows(Some(enum_proc), LPARAM(&mut pids as *mut _ as isize));
    }
    pids
}

fn extract_icon_data_url(path: &str) -> Option<String> {
    let wide_path = to_wide_null(path);
    let mut info = SHFILEINFOW::default();
    let result = unsafe {
        SHGetFileInfoW(
            PCWSTR(wide_path.as_ptr()),
            Default::default(),
            Some(&mut info),
            size_of::<SHFILEINFOW>() as u32,
            SHGFI_ICON | SHGFI_SMALLICON,
        )
    };

    if result == 0 || info.hIcon.0.is_null() {
        return None;
    }

    let encoded = icon_to_data_url(info.hIcon);
    unsafe {
        let _ = DestroyIcon(info.hIcon);
    }
    encoded
}

fn icon_to_data_url(icon: windows::Win32::UI::WindowsAndMessaging::HICON) -> Option<String> {
    const ICON_SIZE: i32 = 32;
    let hdc = unsafe { CreateCompatibleDC(None) };
    if hdc.0.is_null() {
        return None;
    }

    let mut bits: *mut c_void = null_mut();
    let bitmap_info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: ICON_SIZE,
            biHeight: -ICON_SIZE,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        },
        ..Default::default()
    };

    let bitmap =
        match unsafe { CreateDIBSection(hdc, &bitmap_info, DIB_RGB_COLORS, &mut bits, None, 0) } {
            Ok(bitmap) => bitmap,
            Err(_) => {
                unsafe {
                    let _ = DeleteDC(hdc);
                }
                return None;
            }
        };

    if bitmap.0.is_null() || bits.is_null() {
        unsafe {
            let _ = DeleteDC(hdc);
        }
        return None;
    }

    let previous = unsafe { SelectObject(hdc, HGDIOBJ(bitmap.0)) };
    let drawn =
        unsafe { DrawIconEx(hdc, 0, 0, icon, ICON_SIZE, ICON_SIZE, 0, None, DI_NORMAL).is_ok() };

    let encoded = if drawn {
        let raw = unsafe {
            slice::from_raw_parts(bits as *const u8, (ICON_SIZE * ICON_SIZE * 4) as usize)
        };
        let mut rgba = Vec::with_capacity(raw.len());
        for pixel in raw.chunks_exact(4) {
            rgba.push(pixel[2]);
            rgba.push(pixel[1]);
            rgba.push(pixel[0]);
            rgba.push(pixel[3]);
        }
        let image = RgbaImage::from_raw(ICON_SIZE as u32, ICON_SIZE as u32, rgba)?;
        let mut png = Vec::new();
        PngEncoder::new(&mut png)
            .write_image(
                image.as_raw(),
                ICON_SIZE as u32,
                ICON_SIZE as u32,
                ColorType::Rgba8.into(),
            )
            .ok()?;
        Some(format!(
            "data:image/png;base64,{}",
            general_purpose::STANDARD.encode(png)
        ))
    } else {
        None
    };

    unsafe {
        if !previous.0.is_null() {
            let _ = SelectObject(hdc, previous);
        }
        let _ = DeleteObject(HGDIOBJ(bitmap.0));
        let _ = DeleteDC(hdc);
    }

    encoded
}

fn wide_fixed_to_string(buffer: &[u16]) -> String {
    let len = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..len])
}

fn to_wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            list_processes,
            pick_dlls,
            load_settings,
            save_settings,
            inject_dlls,
            window_minimize,
            window_toggle_maximize,
            window_close,
            start_window_drag
        ])
        .run(tauri::generate_context!())
        .expect("failed to run EZInject");
}
