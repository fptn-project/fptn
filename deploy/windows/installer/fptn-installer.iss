// replacement automatically
#define APP_VERSION_NAME "1.0.0"
// replacement automatically
#define APP_VERSION_NUMBER "1.0.0"
// replacement automatically
#define APP_COPYRIGHT_YEAR "2024"

#define APP_ID				"{D2D2C1f8-5F5F-5f79-9C5F-7E2B9F1C39A4}"
#define APP_URL 			"fptn.org"
#define APP_NAME 			"FPTN Client"
#define APP_PUBLISHER 		"fptn.org"

[Setup]
AppId={{#APP_ID}
AppName={#APP_NAME}
AppVersion={#APP_VERSION_NAME}

MinVersion=10.0.10240
AppPublisher={#APP_PUBLISHER}
AppPublisherURL={#APP_URL}
AppSupportURL={#APP_URL}
AppUpdatesURL={#APP_URL}
DefaultDirName={autopf}\{#APP_NAME}
DefaultGroupName={#APP_NAME}
OutputDir=Output
OutputBaseFilename=FptnClientInstaller
SetupIconFile=resources\icons\app.ico
Compression=lzma
SolidCompression=yes
DisableDirPage=no
// # LicenseFile=installer\license\LicenseFile.rtf
VersionInfoVersion={#APP_VERSION_NUMBER}
WizardStyle=modern
UninstallLogMode=overwrite
AppCopyright=Copyright (C) {#APP_COPYRIGHT_YEAR} {#APP_PUBLISHER}.
PrivilegesRequired=admin
AppendDefaultDirName=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
SetupLogging=Yes

[Dirs]
Name: "{app}\";
Name: "{app}\logs";
Name: "{app}\plugins";

[Files]
Source: "depends/qt/*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs uninsneveruninstall
Source: "depends/wintun.dll"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs uninsneveruninstall
Source: "depends/fptn-client.exe"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs uninsneveruninstall
Source: "depends/fptn-client-cli.exe"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs uninsneveruninstall
Source: "depends/vc_redist.exe"; DestDir: "{tmp}"; AfterInstall: InstallVCRedist(); Flags: ignoreversion recursesubdirs createallsubdirs
// ------- generate bat files -------
Source: "depends/wintun.dll"; DestDir: "{app}"; AfterInstall: GenerateBatFile('{app}\fptn-client.exe','{app}\FptnClient.bat'); Flags: ignoreversion recursesubdirs createallsubdirs uninsneveruninstall
// ------- copy SNI files -------
Source: "depends/sni/*"; DestDir: "{app}\SNI"; Flags: ignoreversion recursesubdirs createallsubdirs

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}";
// --- Name: "startup"; Description: {cm:AutoStartProgram,{#APP_NAME}};

[Run]
// Filename: "cmd.exe"; Parameters: "/c reg add ""HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"" /v IPEnableRouter /t REG_DWORD /d 1 /f"; Flags: runhidden
Filename: "{app}\FptnClient.bat"; Description: "{cm:LaunchProgram,{#APP_NAME}}"; Flags: nowait postinstall skipifdoesntexist

[UninstallRun]
Filename: "taskkill"; Parameters: "/F /IM fptn-client.exe"; Flags: runhidden waituntilterminated
Filename: "taskkill"; Parameters: "/F /IM fptn-client-cli.exe"; Flags: runhidden waituntilterminated

[Icons]
Name: "{group}\{#APP_NAME}"; Filename: "{app}\fptn-client.exe"
Name: "{group}\{cm:UninstallProgram,{#APP_NAME}}"; Filename: "{uninstallexe}";
Name: "{commondesktop}\{#APP_NAME}"; Filename: "{app}\fptn-client.exe"; Tasks: desktopicon
// --- Name: "{userstartup}\{#APP_NAME}"; Filename: "{app}\fptn-client.exe"; Tasks: startup
// --- Name: "{userstartup}\{#APP_NAME}"; Filename: "{app}\FptnClient.bat"; Tasks: startup


[InstallDelete]
Type: filesandordirs; Name: "{app}\qt"
Type: filesandordirs; Name: "{app}\bin"
Type: filesandordirs; Name: "{app}\SNI"
Type: filesandordirs; Name: "{app}\logs"
Type: filesandordirs; Name: "{app}\plugins"
Type: files; Name: "{app}\*"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\qt"
Type: filesandordirs; Name: "{app}\bin"
Type: filesandordirs; Name: "{app}\SNI"
Type: filesandordirs; Name: "{app}\logs"
Type: filesandordirs; Name: "{app}\plugins"
Type: files; Name: "{app}\*"

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
// "English" seems to always break the default language detection with unknown reasons.
Name: "polish"; MessagesFile: "compiler:Languages\Polish.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "ukrainian"; MessagesFile: "compiler:Languages\Ukrainian.isl"


[Code]

function cmd(command: string): integer;
begin
	exec('cmd.exe', 
		'/c ' + command, 
		ExpandConstant('{app}'), 
		SW_HIDE, 
		ewwaituntilterminated, 
		result
	)
end;

procedure InstallVCRedist();
var
    ExitCode: Integer;
begin 
    exec(ExpandConstant(CurrentFileName),
        '',
        ExpandConstant('{app}'),
        SW_SHOWNORMAL,
        ewwaituntilterminated,
        ExitCode);
    //MsgBox('Failed to install Visual C++ Redistributable.', mbError, MB_OK);
end;

procedure GenerateBatFile(programPath: String; batFilePath: String);
var
    content: String;
begin
	content := '@echo off' + #13#10
		+ ExpandConstant('cd "{app}"') + #13#10
		+ 'Net session >nul 2>&1 || (PowerShell start -verb runas ' + #39 + '%~0' + #39 +' &exit /b)' + #13#10
		+ 'cmd /c start "" "' + ExpandConstant(programPath)  + ' ' + #13#10
		+ 'exit /s';
	SaveStringToFile(ExpandConstant(batFilePath), content, False);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  	if CurStep = ssPostInstall then
  	begin
		//if MsgBox('The installation has completed. For changes to take effect, please restart your computer. Do you want to restart now?', mbConfirmation, MB_YESNO) = IDYES then
        //begin
        //    cmd('shutdown /r /t 0');
        //end;
  	end;
end;
