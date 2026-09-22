; bwssh installer (Inno Setup 6)
; Build: ISCC /DAppVersion=1.2.3 /DPublishDir=..\artifacts\publish installer\bwssh.iss

#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#ifndef PublishDir
  #define PublishDir "..\artifacts\publish"
#endif
#ifndef OutputDir
  #define OutputDir "..\artifacts\installer"
#endif

#define AppName "bwssh"
#define AppExe "bwssh.exe"

[Setup]
AppId={{6F2B8C1E-4A7D-4E5B-9C3A-8D1F0B2E7A64}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=luoxiaoxin123
AppPublisherURL=https://github.com/luoxiaoxin123/bwssh
AppSupportURL=https://github.com/luoxiaoxin123/bwssh/issues
DefaultDirName={localappdata}\Programs\{#AppName}
DisableProgramGroupPage=yes
DisableDirPage=auto
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.19041
OutputDir={#OutputDir}
OutputBaseFilename=bwssh-setup-{#AppVersion}
SetupIconFile=..\src\BwSshAgent.App\Assets\app.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
AppMutex=BwSshAgent-AppMutex
CloseApplications=force
RestartApplications=no
LicenseFile=..\LICENSE

[Languages]
Name: "chinesesimplified"; MessagesFile: "ChineseSimplified.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
chinesesimplified.AutoStart=开机时自动启动（在托盘中后台运行）
english.AutoStart=Start automatically when I sign in (runs in the tray)
chinesesimplified.DesktopIcon=创建桌面快捷方式
english.DesktopIcon=Create a desktop shortcut
chinesesimplified.Launch=启动 bwssh
english.Launch=Launch bwssh
chinesesimplified.PurgeData=是否同时删除本机数据？%n%n包括缓存的加密密码库、设置、审计日志、PIN 和 Windows Hello 解锁设置。%n选择“否”则保留，重新安装后可以直接使用。
english.PurgeData=Also delete local data?%n%nThis removes the cached encrypted vault, settings, audit log, PIN and Windows Hello unlock.%nChoose No to keep it for a later reinstall.

[Tasks]
Name: "autostart"; Description: "{cm:AutoStart}"
Name: "desktopicon"; Description: "{cm:DesktopIcon}"; Flags: unchecked

[Files]
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "BwSshAgent"; ValueData: """{app}\{#AppExe}"" --background"; Tasks: autostart; Flags: uninsdeletevalue

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:Launch}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
var
  PurgeData: Boolean;

function InitializeUninstall(): Boolean;
begin
  PurgeData := False;
  if not UninstallSilent() then
    PurgeData := MsgBox(ExpandConstant('{cm:PurgeData}'), mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;
  Result := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
  Params: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    Params := '--uninstall-cleanup';
    if PurgeData then
      Params := Params + ' --purge';
    Exec(ExpandConstant('{app}\{#AppExe}'), Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;
