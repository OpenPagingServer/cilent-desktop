#define MyInstallerName "Open Paging Server Desktop"
#define MyShortcutName "Open Paging Server"
#define MyAppVersion "0.5.0"
#define MyAppPublisher "Open Paging Server"
#define MyAppExeName "OpenPagingServerClient.exe"

[Setup]
AppId={{7C1B9A64-52D4-4E7B-9F3A-0E8A2C6D51B0}
AppName={#MyInstallerName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyInstallerName}
DefaultGroupName={#MyShortcutName}
DisableProgramGroupPage=yes
OutputDir=dist
OutputBaseFilename=OpenPagingServerClientSetup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
CloseApplications=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "startupicon"; Description: "Launch the client when Windows starts"; GroupDescription: "Additional options:"

[Files]
Source: "dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyShortcutName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyShortcutName}"; Filename: "{app}\{#MyAppExeName}"

[Registry]
Root: HKA; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "OpenPagingServerClient"; ValueData: """{app}\{#MyAppExeName}"""; Flags: uninsdeletevalue; Tasks: startupicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyShortcutName}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{cmd}"; Parameters: "/C taskkill /IM ""{#MyAppExeName}"" /T >nul 2>&1 || exit /B 0"; Flags: runhidden
Filename: "{cmd}"; Parameters: "/C taskkill /IM ""{#MyAppExeName}"" /F /T >nul 2>&1 || exit /B 0"; Flags: runhidden