import { invoke } from "@tauri-apps/api/core";
import confetti from "canvas-confetti";
import {
  Activity,
  AlertTriangle,
  Bell,
  Check,
  ChevronDown,
  Clock3,
  FileCode2,
  Filter,
  ListRestart,
  Loader2,
  Maximize2,
  Minus,
  Play,
  Plus,
  Search,
  Settings2,
  SortAsc,
  Target,
  Trash2,
  X
} from "lucide-react";
import type { ReactNode } from "react";
import { MouseEvent, useEffect, useMemo, useState } from "react";

type TargetMode = "processName" | "exePath" | "pid";
type ProcessSort = "created" | "az";
type ProcessFilter = "all" | "user" | "window" | "selected";

type ProcessEntry = {
  pid: number;
  processName: string;
  exeName: string;
  exePath?: string | null;
  iconDataUrl?: string | null;
  createdAtMs?: number | null;
  isUserProcess: boolean;
  hasWindow: boolean;
};

type DllEntry = {
  path: string;
  enabled: boolean;
};

type SelectedTarget = {
  mode: TargetMode;
  value: string;
  label: string;
};

type Profile = {
  id: string;
  name: string;
  selectedTarget?: SelectedTarget | null;
  dlls: DllEntry[];
};

type AppSettings = {
  refreshIntervalMs: number;
  processSort: ProcessSort;
  processFilter: ProcessFilter;
  successPopupEnabled: boolean;
  successPopupDurationMs: number;
  confettiEnabled: boolean;
  shakeEnabled: boolean;
  focusOnInject: boolean;
  overrideAlreadyLoaded?: boolean;
  activeProfileId: string;
  profiles: Profile[];
  selectedTarget?: SelectedTarget | null;
  dlls?: DllEntry[];
};

type InjectionResult = {
  dllPath: string;
  success: boolean;
  alreadyLoaded: boolean;
  message: string;
};

type LogEntry = {
  id: string;
  level: "info" | "success" | "error";
  message: string;
  timestamp: string;
};

type ContextMenuState = {
  x: number;
  y: number;
  dllPath: string;
};

const DEFAULT_SETTINGS: AppSettings = {
  refreshIntervalMs: 5000,
  processSort: "created",
  processFilter: "all",
  successPopupEnabled: true,
  successPopupDurationMs: 5000,
  confettiEnabled: true,
  shakeEnabled: true,
  focusOnInject: false,
  overrideAlreadyLoaded: undefined,
  activeProfileId: "main",
  profiles: [
    {
      id: "main",
      name: "Main",
      selectedTarget: null,
      dlls: []
    }
  ]
};

const targetModeLabels: Record<TargetMode, string> = {
  processName: "Process Name",
  exePath: "Exe Path",
  pid: "PID"
};

const filterLabels: Record<ProcessFilter, string> = {
  all: "All Accessible",
  user: "User Processes",
  window: "With Window",
  selected: "Selected Match"
};

const sortLabels: Record<ProcessSort, string> = {
  created: "Time Created",
  az: "A-Z"
};

function pathBaseName(path: string) {
  return path.split(/[\\/]/).filter(Boolean).pop() ?? path;
}

function formatCreatedAt(value?: number | null) {
  if (!value) return "Unknown";
  return new Intl.DateTimeFormat(undefined, {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit"
  }).format(new Date(value));
}

function targetValueForProcess(process: ProcessEntry, mode: TargetMode) {
  if (mode === "pid") return String(process.pid);
  if (mode === "exePath") return process.exePath || process.exeName;
  return process.processName;
}

function targetLabelForProcess(process: ProcessEntry, mode: TargetMode) {
  if (mode === "pid") return `${process.processName} (${process.pid})`;
  if (mode === "exePath") return process.exePath || process.exeName;
  return process.processName;
}

function fallbackIconText(process: ProcessEntry) {
  const name = process.processName || process.exeName || "?";
  return name.slice(0, 2).toUpperCase();
}

function createLog(level: LogEntry["level"], message: string): LogEntry {
  return {
    id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
    level,
    message,
    timestamp: new Intl.DateTimeFormat(undefined, {
      hour: "numeric",
      minute: "2-digit",
      second: "2-digit"
    }).format(new Date())
  };
}

function randomProfileId() {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `profile-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
}

function normalizeProfile(profile: Partial<Profile> | null | undefined, fallbackName = "Main") {
  return {
    id: profile?.id || randomProfileId(),
    name: profile?.name?.trim() || fallbackName,
    selectedTarget: profile?.selectedTarget ?? null,
    dlls: Array.isArray(profile?.dlls) ? profile.dlls : []
  };
}

function normalizeSettings(settings: Partial<AppSettings>): AppSettings {
  const legacyProfile = normalizeProfile({
    id: "main",
    name: "Main",
    selectedTarget: settings.selectedTarget ?? null,
    dlls: settings.dlls ?? []
  });
  const profiles = Array.isArray(settings.profiles) && settings.profiles.length
    ? settings.profiles.map((profile, index) => normalizeProfile(profile, index === 0 ? "Main" : "Profile"))
    : [legacyProfile];
  const activeProfileId = profiles.some((profile) => profile.id === settings.activeProfileId)
    ? settings.activeProfileId!
    : profiles[0].id;

  return {
    ...DEFAULT_SETTINGS,
    ...settings,
    activeProfileId,
    profiles,
    selectedTarget: undefined,
    dlls: undefined
  };
}

function createProfileId(name: string) {
  const slug = name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
  return `${slug || "profile"}-${Date.now().toString(36)}`;
}

type PrettyDropdownOption<T extends string> = {
  value: T;
  label: string;
};

type PrettyDropdownProps<T extends string> = {
  value: T;
  options: PrettyDropdownOption<T>[];
  icon: ReactNode;
  onChange: (value: T) => void;
  ariaLabel: string;
};

function PrettyDropdown<T extends string>({
  value,
  options,
  icon,
  onChange,
  ariaLabel
}: PrettyDropdownProps<T>) {
  const [isOpen, setIsOpen] = useState(false);
  const selected = options.find((option) => option.value === value) ?? options[0];

  useEffect(() => {
    if (!isOpen) return;
    const close = () => setIsOpen(false);
    window.addEventListener("click", close);
    return () => window.removeEventListener("click", close);
  }, [isOpen]);

  return (
    <div className={`pretty-dropdown ${isOpen ? "open" : ""}`} onClick={(event) => event.stopPropagation()}>
      <button
        type="button"
        className="dropdown-trigger"
        aria-label={ariaLabel}
        aria-expanded={isOpen}
        onClick={() => setIsOpen((open) => !open)}
      >
        {icon}
        <span>{selected.label}</span>
        <ChevronDown size={15} />
      </button>
      {isOpen && (
        <div className="dropdown-menu">
          {options.map((option) => (
            <button
              key={option.value}
              type="button"
              className={option.value === value ? "selected" : ""}
              onClick={() => {
                onChange(option.value);
                setIsOpen(false);
              }}
            >
              <span>{option.label}</span>
              {option.value === value && <Check size={15} />}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [settings, setSettings] = useState<AppSettings>(DEFAULT_SETTINGS);
  const [settingsLoaded, setSettingsLoaded] = useState(false);
  const [processes, setProcesses] = useState<ProcessEntry[]>([]);
  const [selectedPid, setSelectedPid] = useState<number | null>(null);
  const [targetMode, setTargetMode] = useState<TargetMode>("processName");
  const [searchTerm, setSearchTerm] = useState("");
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [isProfilesOpen, setIsProfilesOpen] = useState(false);
  const [newProfileName, setNewProfileName] = useState("Debug");
  const [renameProfileName, setRenameProfileName] = useState("Main");
  const [isLoadingProcesses, setIsLoadingProcesses] = useState(false);
  const [isInjecting, setIsInjecting] = useState(false);
  const [progressVisible, setProgressVisible] = useState(false);
  const [progressExiting, setProgressExiting] = useState(false);
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [modal, setModal] = useState<"success" | "failure" | "warning" | null>(null);
  const [rememberOverrideChoice, setRememberOverrideChoice] = useState(false);
  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);
  const [buttonShake, setButtonShake] = useState(false);

  const activeProfile = useMemo(
    () =>
      settings.profiles.find((profile) => profile.id === settings.activeProfileId) ??
      settings.profiles[0] ??
      DEFAULT_SETTINGS.profiles[0],
    [settings.activeProfileId, settings.profiles]
  );

  useEffect(() => {
    invoke<AppSettings>("load_settings")
      .then((loaded) => {
        const merged = normalizeSettings(loaded);
        setSettings(merged);
        const loadedProfile =
          merged.profiles.find((profile) => profile.id === merged.activeProfileId) ?? merged.profiles[0];
        if (loadedProfile.selectedTarget?.mode) {
          setTargetMode(loadedProfile.selectedTarget.mode);
        }
        setRenameProfileName(loadedProfile.name);
        if (merged.profiles.some((profile) => profile.name.toLowerCase() === "debug")) {
          setNewProfileName("Profile");
        }
        setSettingsLoaded(true);
      })
      .catch((error) => {
        setLogs((current) => [
          createLog("error", `Failed to load settings: ${String(error)}`),
          ...current
        ]);
        setSettingsLoaded(true);
      });
  }, []);

  useEffect(() => {
    if (!settingsLoaded) return;
    const timeout = window.setTimeout(() => {
      invoke("save_settings", { settings }).catch((error) => {
        setLogs((current) => [
          createLog("error", `Failed to save settings: ${String(error)}`),
          ...current
        ]);
      });
    }, 250);

    return () => window.clearTimeout(timeout);
  }, [settings, settingsLoaded]);

  useEffect(() => {
    refreshProcesses();
    const interval = window.setInterval(refreshProcesses, settings.refreshIntervalMs);
    return () => window.clearInterval(interval);
  }, [settings.refreshIntervalMs]);

  useEffect(() => {
    const selected = activeProfile.selectedTarget;
    if (!selected) {
      setSelectedPid(null);
      return;
    }

    const match = processes.find((process) => {
      if (selected.mode === "pid") return String(process.pid) === selected.value;
      if (selected.mode === "exePath") {
        return (
          process.exePath?.toLowerCase() === selected.value.toLowerCase() ||
          process.exeName.toLowerCase() === selected.value.toLowerCase()
        );
      }
      return process.processName.toLowerCase() === selected.value.toLowerCase();
    });

    setSelectedPid(match?.pid ?? null);
  }, [activeProfile.selectedTarget, processes]);

  useEffect(() => {
    setRenameProfileName(activeProfile.name);
    if (activeProfile.selectedTarget?.mode) {
      setTargetMode(activeProfile.selectedTarget.mode);
    }
  }, [activeProfile.id, activeProfile.name, activeProfile.selectedTarget?.mode]);

  useEffect(() => {
    if (modal !== "success") return;
    const timeout = window.setTimeout(() => setModal(null), settings.successPopupDurationMs);
    return () => window.clearTimeout(timeout);
  }, [modal, settings.successPopupDurationMs]);

  useEffect(() => {
    const closeContext = () => setContextMenu(null);
    window.addEventListener("click", closeContext);
    window.addEventListener("blur", closeContext);
    return () => {
      window.removeEventListener("click", closeContext);
      window.removeEventListener("blur", closeContext);
    };
  }, []);

  async function refreshProcesses() {
    setIsLoadingProcesses(true);
    try {
      const listed = await invoke<ProcessEntry[]>("list_processes");
      setProcesses(listed);
    } catch (error) {
      setLogs((current) => [
        createLog("error", `Failed to refresh process list: ${String(error)}`),
        ...current
      ]);
    } finally {
      setIsLoadingProcesses(false);
    }
  }

  const filteredProcesses = useMemo(() => {
    const query = searchTerm.trim().toLowerCase();
    const selected = activeProfile.selectedTarget;

    return processes
      .filter((process) => {
        if (settings.processFilter === "user" && !process.isUserProcess) return false;
        if (settings.processFilter === "window" && !process.hasWindow) return false;
        if (settings.processFilter === "selected") {
          if (!selected) return true;
          if (selected.mode === "pid" && String(process.pid) !== selected.value) return false;
          if (
            selected.mode === "exePath" &&
            process.exePath?.toLowerCase() !== selected.value.toLowerCase() &&
            process.exeName.toLowerCase() !== selected.value.toLowerCase()
          ) {
            return false;
          }
          if (
            selected.mode === "processName" &&
            process.processName.toLowerCase() !== selected.value.toLowerCase()
          ) {
            return false;
          }
        }
        if (!query) return true;
        return (
          process.processName.toLowerCase().includes(query) ||
          process.exeName.toLowerCase().includes(query) ||
          (process.exePath ?? "").toLowerCase().includes(query) ||
          String(process.pid).includes(query)
        );
      })
      .sort((a, b) => {
        if (settings.processSort === "az") {
          const byName = a.processName.localeCompare(b.processName, undefined, {
            sensitivity: "base"
          });
          return byName || a.pid - b.pid;
        }
        const aTime = a.createdAtMs ?? 0;
        const bTime = b.createdAtMs ?? 0;
        return bTime - aTime || a.processName.localeCompare(b.processName) || a.pid - b.pid;
      });
  }, [activeProfile.selectedTarget, processes, searchTerm, settings.processFilter, settings.processSort]);

  const enabledDlls = activeProfile.dlls.filter((dll) => dll.enabled);
  const selectedProcess = selectedPid
    ? processes.find((process) => process.pid === selectedPid) ?? null
    : null;

  function updateSettings(patch: Partial<AppSettings>) {
    setSettings((current) => ({ ...current, ...patch }));
  }

  function updateActiveProfile(patch: Partial<Profile>) {
    setSettings((current) => ({
      ...current,
      profiles: current.profiles.map((profile) =>
        profile.id === current.activeProfileId ? { ...profile, ...patch } : profile
      )
    }));
  }

  function switchProfile(profileId: string) {
    const profile = settings.profiles.find((candidate) => candidate.id === profileId);
    if (!profile) return;
    setSettings((current) => ({ ...current, activeProfileId: profileId }));
    setRenameProfileName(profile.name);
    if (profile.selectedTarget?.mode) {
      setTargetMode(profile.selectedTarget.mode);
    }
  }

  function createProfile() {
    const name = newProfileName.trim() || "Profile";
    const profile: Profile = {
      id: createProfileId(name),
      name,
      selectedTarget: null,
      dlls: []
    };
    setSettings((current) => ({
      ...current,
      activeProfileId: profile.id,
      profiles: [...current.profiles, profile]
    }));
    setRenameProfileName(name);
    setNewProfileName(name.toLowerCase() === "debug" ? "Profile" : "Debug");
    setTargetMode("processName");
  }

  function renameActiveProfile() {
    const name = renameProfileName.trim();
    if (!name) return;
    updateActiveProfile({ name });
  }

  function deleteActiveProfile() {
    if (settings.profiles.length <= 1) return;
    setSettings((current) => {
      const nextProfiles = current.profiles.filter((profile) => profile.id !== current.activeProfileId);
      const nextActiveProfile = nextProfiles[0];
      return {
        ...current,
        activeProfileId: nextActiveProfile.id,
        profiles: nextProfiles
      };
    });
  }

  function selectProcess(process: ProcessEntry) {
    const target: SelectedTarget = {
      mode: targetMode,
      value: targetValueForProcess(process, targetMode),
      label: targetLabelForProcess(process, targetMode)
    };
    setSelectedPid(process.pid);
    updateActiveProfile({ selectedTarget: target });
  }

  function changeTargetMode(mode: TargetMode) {
    setTargetMode(mode);
    if (!selectedProcess) return;
    updateActiveProfile({
      selectedTarget: {
        mode,
        value: targetValueForProcess(selectedProcess, mode),
        label: targetLabelForProcess(selectedProcess, mode)
      }
    });
  }

  async function chooseDlls() {
    try {
      const paths = await invoke<string[]>("pick_dlls");
      if (!paths.length) return;
      setSettings((current) => {
        const profile = current.profiles.find((candidate) => candidate.id === current.activeProfileId);
        const currentDlls = profile?.dlls ?? [];
        const existing = new Set(currentDlls.map((dll) => dll.path.toLowerCase()));
        const additions = paths
          .filter((path) => !existing.has(path.toLowerCase()))
          .map((path) => ({ path, enabled: true }));
        return {
          ...current,
          profiles: current.profiles.map((candidate) =>
            candidate.id === current.activeProfileId
              ? { ...candidate, dlls: [...currentDlls, ...additions] }
              : candidate
          )
        };
      });
    } catch (error) {
      setLogs((current) => [
        createLog("error", `DLL picker failed: ${String(error)}`),
        ...current
      ]);
    }
  }

  function toggleDll(path: string) {
    setSettings((current) => ({
      ...current,
      profiles: current.profiles.map((profile) =>
        profile.id === current.activeProfileId
          ? {
              ...profile,
              dlls: profile.dlls.map((dll) =>
                dll.path === path ? { ...dll, enabled: !dll.enabled } : dll
              )
            }
          : profile
      )
    }));
  }

  function removeDll(path: string) {
    setSettings((current) => ({
      ...current,
      profiles: current.profiles.map((profile) =>
        profile.id === current.activeProfileId
          ? { ...profile, dlls: profile.dlls.filter((dll) => dll.path !== path) }
          : profile
      )
    }));
  }

  function openDllMenu(event: MouseEvent, dllPath: string) {
    event.preventDefault();
    event.stopPropagation();
    setContextMenu({ x: event.clientX, y: event.clientY, dllPath });
  }

  async function inject(overrideAlreadyLoaded = settings.overrideAlreadyLoaded ?? false) {
    const target = activeProfile.selectedTarget;
    if (!target) {
      setLogs((current) => [createLog("error", "Select a process before injecting."), ...current]);
      setModal("failure");
      return;
    }

    if (!enabledDlls.length) {
      setLogs((current) => [createLog("error", "Add at least one enabled DLL."), ...current]);
      setModal("failure");
      return;
    }

    setIsInjecting(true);
    setProgressVisible(true);
    setProgressExiting(false);
    setProgress(8);
    const progressTimer = window.setInterval(() => {
      setProgress((current) => Math.min(current + Math.max(2, (90 - current) * 0.12), 90));
    }, 180);

    try {
      const results = await invoke<InjectionResult[]>("inject_dlls", {
        target,
        dlls: enabledDlls,
        focusOnInject: settings.focusOnInject,
        overrideAlreadyLoaded
      });
      window.clearInterval(progressTimer);
      setProgress(100);

      const failures = results.filter((result) => !result.success);
      const alreadyLoaded = results.filter((result) => result.alreadyLoaded);
      const successes = results.filter((result) => result.success && !result.alreadyLoaded);
      const entries = results.map((result) =>
        createLog(
          result.success ? (result.alreadyLoaded ? "info" : "success") : "error",
          `${pathBaseName(result.dllPath)}: ${result.message}`
        )
      );

      setLogs((current) => [...entries.reverse(), ...current]);

      if (failures.length > 0) {
        setModal("failure");
      } else if (alreadyLoaded.length > 0 && !overrideAlreadyLoaded && settings.overrideAlreadyLoaded == null) {
        setModal("warning");
      } else if (successes.length > 0) {
        if (settings.shakeEnabled) {
          setButtonShake(true);
          window.setTimeout(() => setButtonShake(false), 620);
        }
        if (settings.confettiEnabled) {
          confetti({
            particleCount: 110,
            spread: 74,
            origin: { y: 0.78 },
            colors: ["#725AC1", "#8D86C9", "#F7ECE1", "#3f335f"]
          });
        }
        if (settings.successPopupEnabled) {
          setModal("success");
        }
      }
    } catch (error) {
      window.clearInterval(progressTimer);
      setProgress(100);
      setLogs((current) => [
        createLog("error", `Injection failed: ${String(error)}`),
        ...current
      ]);
      setModal("failure");
    } finally {
      window.setTimeout(() => {
        setProgressExiting(true);
        window.setTimeout(() => {
          setProgressVisible(false);
          setProgressExiting(false);
          setProgress(0);
        }, 420);
      }, 300);
      setIsInjecting(false);
    }
  }

  function onOverrideYes() {
    if (rememberOverrideChoice) {
      updateSettings({ overrideAlreadyLoaded: true });
    }
    setModal(null);
    inject(true);
  }

  function onOverrideNo() {
    if (rememberOverrideChoice) {
      updateSettings({ overrideAlreadyLoaded: false });
    }
    setModal(null);
  }

  function dontShowSuccessAgain() {
    updateSettings({
      successPopupEnabled: false
    });
    setModal(null);
  }

  function startDrag(event: MouseEvent) {
    if (event.buttons !== 1) return;
    const target = event.target as HTMLElement;
    if (target.closest("button, input, select, .no-drag")) return;
    invoke("start_window_drag").catch(() => undefined);
  }

  const selectedAvailable = Boolean(selectedProcess);

  const injectDisabledReason = useMemo(() => {
    if (isInjecting) return "Injection in progress…";
    if (!activeProfile.selectedTarget) return "Select a process to inject into";
    if (!selectedAvailable) return "Selected process is not running";
    if (!activeProfile.dlls.length) return "Add at least one DLL";
    if (!enabledDlls.length) return "Enable at least one DLL";
    return null;
  }, [isInjecting, activeProfile.selectedTarget, selectedAvailable, activeProfile.dlls.length, enabledDlls.length]);

  return (
    <main className="app-shell">
      <header className="titlebar" onMouseDown={startDrag}>
        <div className="brand-block">
          <div className="brand-mark">
            <img src="/icon.png" alt="" />
          </div>
          <div>
            <h1>EZInject</h1>
            <span>LoadLibrary injector</span>
          </div>
        </div>
        <div className="window-actions no-drag">
          <button aria-label="Minimize" onClick={() => invoke("window_minimize")}>
            <Minus size={16} />
          </button>
          <button aria-label="Up size" onClick={() => invoke("window_toggle_maximize")}>
            <Maximize2 size={15} />
          </button>
          <button aria-label="Close" className="close" onClick={() => invoke("window_close")}>
            <X size={16} />
          </button>
        </div>
      </header>

      <section className="content-grid">
        <section className="process-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Target Process</p>
              <h2>Processes</h2>
            </div>
            <button className="icon-button" aria-label="Refresh processes" onClick={refreshProcesses}>
              {isLoadingProcesses ? <Loader2 className="spin" size={18} /> : <ListRestart size={18} />}
            </button>
          </div>

          <div className="process-controls">
            <label className="search-box">
              <Search size={17} />
              <input
                value={searchTerm}
                onChange={(event) => setSearchTerm(event.target.value)}
                placeholder="Search name, path, or PID"
              />
            </label>
            <PrettyDropdown
              value={settings.processSort}
              options={(Object.entries(sortLabels) as [ProcessSort, string][]).map(([value, label]) => ({
                value,
                label
              }))}
              icon={<SortAsc size={16} />}
              ariaLabel="Sort processes"
              onChange={(processSort) => updateSettings({ processSort })}
            />
            <PrettyDropdown
              value={settings.processFilter}
              options={(Object.entries(filterLabels) as [ProcessFilter, string][]).map(([value, label]) => ({
                value,
                label
              }))}
              icon={<Filter size={16} />}
              ariaLabel="Filter processes"
              onChange={(processFilter) => updateSettings({ processFilter })}
            />
          </div>

          <div className="target-mode">
            {(Object.keys(targetModeLabels) as TargetMode[]).map((mode) => (
              <button
                key={mode}
                className={targetMode === mode ? "active" : ""}
                onClick={() => changeTargetMode(mode)}
              >
                {targetModeLabels[mode]}
              </button>
            ))}
          </div>

          <div className="process-list">
            {filteredProcesses.map((process) => {
              const isSelected = process.pid === selectedPid;
              return (
                <button
                  key={process.pid}
                  className={`process-row ${isSelected ? "selected" : ""}`}
                  onClick={() => selectProcess(process)}
                >
                  <div className="process-icon">
                    {process.iconDataUrl ? (
                      <img src={process.iconDataUrl} alt="" />
                    ) : (
                      <span>{fallbackIconText(process)}</span>
                    )}
                  </div>
                  <div className="process-main">
                    <div className="process-title-line">
                      <strong>{process.processName}</strong>
                      <span>PID {process.pid}</span>
                    </div>
                    <p>{process.exePath || process.exeName}</p>
                    <div className="process-meta">
                      <span>
                        <Clock3 size={13} />
                        {formatCreatedAt(process.createdAtMs)}
                      </span>
                      <span>{process.isUserProcess ? "User" : "Other"}</span>
                      {process.hasWindow && <span>Window</span>}
                    </div>
                  </div>
                </button>
              );
            })}
            {!filteredProcesses.length && (
              <div className="empty-state">
                <Activity size={20} />
                <span>No matching processes</span>
              </div>
            )}
          </div>
        </section>

        <section className="workspace-panel">
          <div className="profile-panel">
            <div className="profile-heading">
              <div>
                <p className="eyebrow">Profile</p>
                <h2>{activeProfile.name}</h2>
              </div>
              <button
                className="settings-button"
                onClick={() => setIsProfilesOpen((open) => !open)}
              >
                <Target size={18} />
                Profiles
              </button>
            </div>

            <div className="profile-tabs">
              {settings.profiles.map((profile) => (
                <button
                  key={profile.id}
                  className={profile.id === activeProfile.id ? "active" : ""}
                  onClick={() => switchProfile(profile.id)}
                >
                  <strong>{profile.name}</strong>
                  <span>{profile.dlls.filter((dll) => dll.enabled).length} enabled</span>
                </button>
              ))}
            </div>

            {isProfilesOpen && (
              <div className="profile-manager">
                <label className="profile-input">
                  <span>New profile</span>
                  <input
                    value={newProfileName}
                    onChange={(event) => setNewProfileName(event.target.value)}
                    placeholder="Debug"
                  />
                </label>
                <button className="secondary-button" onClick={createProfile}>
                  <Plus size={18} />
                  Create
                </button>
                <label className="profile-input">
                  <span>Rename active</span>
                  <input
                    value={renameProfileName}
                    onChange={(event) => setRenameProfileName(event.target.value)}
                  />
                </label>
                <button className="secondary-button" onClick={renameActiveProfile}>
                  <Check size={18} />
                  Rename
                </button>
                <button
                  className="danger-button"
                  disabled={settings.profiles.length <= 1}
                  onClick={deleteActiveProfile}
                >
                  <Trash2 size={18} />
                  Delete
                </button>
              </div>
            )}
          </div>

          <div className="selected-target">
            <div>
              <p className="eyebrow">Selected Target</p>
              <h2>{activeProfile.selectedTarget?.label || "No process selected"}</h2>
              <p className={selectedAvailable ? "target-live" : "target-missing"}>
                {activeProfile.selectedTarget
                  ? selectedAvailable
                    ? `${targetModeLabels[activeProfile.selectedTarget.mode]}: ${activeProfile.selectedTarget.value}`
                    : "Saved target is not currently available"
                  : "Choose a process from the list"}
              </p>
            </div>
            <button className="settings-button" onClick={() => setIsSettingsOpen((open) => !open)}>
              <Settings2 size={18} />
              Settings
            </button>
          </div>

          {isSettingsOpen && (
            <div className="quick-settings">
              <div className="setting-row">
                <label>Refresh</label>
                <div className="range-row">
                  <input
                    type="range"
                    min="1000"
                    max="15000"
                    step="500"
                    value={settings.refreshIntervalMs}
                    onChange={(event) =>
                      updateSettings({ refreshIntervalMs: Number(event.target.value) })
                    }
                  />
                  <span>{(settings.refreshIntervalMs / 1000).toFixed(1)}s</span>
                </div>
              </div>
              <button
                className={`state-toggle ${settings.confettiEnabled ? "on" : "off"}`}
                onClick={() => updateSettings({ confettiEnabled: !settings.confettiEnabled })}
              >
                <span>Confetti</span>
                <strong>{settings.confettiEnabled ? "On" : "Off"}</strong>
              </button>
              <button
                className={`state-toggle ${settings.shakeEnabled ? "on" : "off"}`}
                onClick={() => updateSettings({ shakeEnabled: !settings.shakeEnabled })}
              >
                <span>Inject shake</span>
                <strong>{settings.shakeEnabled ? "On" : "Off"}</strong>
              </button>
              <button
                className={`state-toggle ${settings.focusOnInject ? "on" : "off"}`}
                onClick={() => updateSettings({ focusOnInject: !settings.focusOnInject })}
              >
                <span>Focus on inject</span>
                <strong>{settings.focusOnInject ? "On" : "Off"}</strong>
              </button>
              <button
                className={`state-toggle ${settings.successPopupEnabled ? "on" : "off"}`}
                onClick={() =>
                  updateSettings({
                    successPopupEnabled: !settings.successPopupEnabled
                  })
                }
              >
                <span>Success popup</span>
                <strong>{settings.successPopupEnabled ? "On" : "Off"}</strong>
              </button>
              <button
                className={`state-toggle ${settings.overrideAlreadyLoaded === true ? "on" : settings.overrideAlreadyLoaded === false ? "off" : ""}`}
                onClick={() =>
                  updateSettings({
                    overrideAlreadyLoaded:
                      settings.overrideAlreadyLoaded === undefined
                        ? true
                        : settings.overrideAlreadyLoaded === true
                          ? false
                          : undefined
                  })
                }
              >
                <span>Override already loaded</span>
                <strong>
                  {settings.overrideAlreadyLoaded === true
                    ? "Yes"
                    : settings.overrideAlreadyLoaded === false
                      ? "No"
                      : "Ask"}
                </strong>
              </button>
              <div className="setting-row">
                <label>Success popup close</label>
                <div className="range-row">
                  <input
                    type="range"
                    min="1500"
                    max="10000"
                    step="500"
                    value={settings.successPopupDurationMs}
                    onChange={(event) =>
                      updateSettings({ successPopupDurationMs: Number(event.target.value) })
                    }
                  />
                  <span>{(settings.successPopupDurationMs / 1000).toFixed(1)}s</span>
                </div>
              </div>
            </div>
          )}

          <div className="dll-section">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Payloads</p>
                <h2>DLLs</h2>
              </div>
              <button className="secondary-button" onClick={chooseDlls}>
                <Plus size={18} />
                Add DLLs
              </button>
            </div>

            <div className="dll-list">
              {activeProfile.dlls.map((dll) => (
                <div
                  key={dll.path}
                  className={`dll-row ${dll.enabled ? "" : "disabled"}`}
                  onContextMenu={(event) => openDllMenu(event, dll.path)}
                >
                  <div className="dll-icon">
                    <FileCode2 size={18} />
                  </div>
                  <div>
                    <strong>{pathBaseName(dll.path)}</strong>
                    <p>{dll.path}</p>
                  </div>
                  <button className="small-pill" onClick={() => toggleDll(dll.path)}>
                    {dll.enabled ? "Enabled" : "Disabled"}
                  </button>
                </div>
              ))}
              {!activeProfile.dlls.length && (
                <div className="empty-state">
                  <FileCode2 size={20} />
                  <span>No DLLs selected</span>
                </div>
              )}
            </div>
          </div>

          <div
            className="inject-button-wrap"
            data-tooltip={injectDisabledReason ?? undefined}
          >
            <button
              className={`inject-button ${buttonShake ? "shake" : ""}`}
              disabled={Boolean(injectDisabledReason)}
              onClick={() => inject()}
            >
              {isInjecting ? <Loader2 className="spin" size={24} /> : <Play size={24} />}
              Inject
            </button>
          </div>

          {progressVisible && (
            <div className={`progress-pop ${progressExiting ? "exit" : ""}`}>
              <div className="progress-copy">
                <span>{isInjecting ? "Injecting DLLs" : "Injection complete"}</span>
                <strong>{Math.round(progress)}%</strong>
              </div>
              <div className="progress-track">
                <div className="progress-fill" style={{ width: `${progress}%` }} />
              </div>
            </div>
          )}

          <section className="log-panel">
            <div className="section-heading compact">
              <div>
                <p className="eyebrow">Runtime</p>
                <h2>Log</h2>
              </div>
              <button className="icon-button" aria-label="Clear log" onClick={() => setLogs([])}>
                <Trash2 size={17} />
              </button>
            </div>
            <div className="log-list">
              {logs.map((log) => (
                <div key={log.id} className={`log-row ${log.level}`}>
                  <span>{log.timestamp}</span>
                  <p>{log.message}</p>
                </div>
              ))}
              {!logs.length && <div className="empty-log">No log entries yet</div>}
            </div>
          </section>
        </section>
      </section>

      {contextMenu && (
        <div
          className="context-menu no-drag"
          style={{ left: contextMenu.x, top: contextMenu.y }}
          onClick={(event) => event.stopPropagation()}
        >
          <button
            onClick={() => {
              toggleDll(contextMenu.dllPath);
            }}
          >
            <Check size={15} />
            {activeProfile.dlls.find((dll) => dll.path === contextMenu.dllPath)?.enabled
              ? "Disable for now"
              : "Enable"}
          </button>
          <button
            onClick={() => {
              removeDll(contextMenu.dllPath);
              setContextMenu(null);
            }}
          >
            <Trash2 size={15} />
            Remove
          </button>
        </div>
      )}

      {modal && (
        <div className="modal-backdrop">
          <div className={`result-modal ${modal}`}>
            {modal !== "warning" && (
              <button className="modal-close" aria-label="Close popup" onClick={() => setModal(null)}>
                <X size={17} />
              </button>
            )}
            <div className="modal-icon">
              {modal === "success" ? (
                <Check size={26} />
              ) : modal === "warning" ? (
                <AlertTriangle size={26} />
              ) : (
                <AlertTriangle size={26} />
              )}
            </div>
            <h2>
              {modal === "success"
                ? "DLL Injected"
                : modal === "warning"
                  ? "Already Loaded"
                  : "DLL Injection Failed"}
            </h2>
            <p>
              {modal === "success"
                ? "Enabled DLLs were loaded into the selected process."
                : modal === "warning"
                  ? "One or more DLLs are already loaded in the target process. Override and reload them?"
                  : "One or more DLLs failed. Check the log for details."}
            </p>
            {modal === "warning" && (
              <>
                <label className="modal-checkbox">
                  <input
                    type="checkbox"
                    checked={rememberOverrideChoice}
                    onChange={(e) => setRememberOverrideChoice(e.target.checked)}
                  />
                  <span>Remember my choice</span>
                </label>
                <div className="modal-actions">
                  <button className="secondary-button" onClick={onOverrideNo}>
                    No
                  </button>
                  <button className="primary-button" onClick={onOverrideYes}>
                    Yes
                  </button>
                </div>
              </>
            )}
            {modal === "success" && (
              <button className="ghost-button" onClick={dontShowSuccessAgain}>
                <Bell size={16} />
                Don&apos;t Show this again
              </button>
            )}
          </div>
        </div>
      )}
    </main>
  );
}
