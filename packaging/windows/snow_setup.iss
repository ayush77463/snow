; Inno Setup 6 Script for SNOW Windows Distribution
; Builds a self-contained, user-level or system-wide Windows installer.

#define MyAppName "SNOW"
#define MyAppVersion "5.2.0"
#define MyAppPublisher "SNOW Project"
#define MyAppURL "https://github.com/ayush/snow"
#define MyAppExeName "snow.exe"
#define MyTrayExeName "snow-tray.exe"

[Setup]
; Basic Application Info
AppId={{5F7A9B32-E841-4D68-9A7B-8B04A26C4E19}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}

; Installation Directory (User-level local app data: no admin rights required)
DefaultDirName={localappdata}\Programs\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes

; Output Configuration
OutputDir=..\output
OutputBaseFilename=SNOW-Setup-{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern

; Privileges
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

; Uninstaller configuration
SetupIconFile=snow.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName} (AI Multi-Device Bridge)

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "Start SNOW System Tray automatically on Windows login"; GroupDescription: "Startup:"

[Files]
; Install all files collected by PyInstaller into {app}
Source: "..\..\dist\snow\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; Explicit inclusion of verified bundled Cloudflare tunnel binary
Source: "..\..\dist\snow\bin\cloudflared.exe"; DestDir: "{app}\bin"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
; Start Menu Shortcuts
Name: "{group}\SNOW System Tray"; Filename: "{app}\{#MyTrayExeName}"; WorkingDir: "{app}"
Name: "{group}\SNOW Web Dashboard"; Filename: "{app}\{#MyAppExeName}"; Parameters: "web"; WorkingDir: "{app}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"

; Optional Desktop Shortcut
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyTrayExeName}"; Tasks: desktopicon; WorkingDir: "{app}"

[Registry]
; Configure HKCU Run key if user checked autostart task
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "SNOW"; ValueData: """{app}\{#MyTrayExeName}"""; Flags: uninsdeletevalue; Tasks: autostart

[Run]
; Option to launch SNOW Tray upon installation completion
Filename: "{app}\{#MyTrayExeName}"; Description: "Launch SNOW System Tray Companion"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Clean up local runtime databases, caches, and logs upon uninstall
Type: files; Name: "{localappdata}\Programs\{#MyAppName}\*"

[Code]
// Custom Inno Setup Pascal script for pre-uninstall cleanup
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    // Attempt graceful daemon stop before deleting files
    Exec(ExpandConstant('{app}\{#MyAppExeName}'), 'daemon stop', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;
