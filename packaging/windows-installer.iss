; AegorX Windows installer (Inno Setup 6)
; Built by CI: ISCC packaging/windows-installer.iss
; The .exe installed here is the PyInstaller standalone build.

#define AppName "AegorX"
#ifndef AppVersion
#define AppVersion GetEnv("AEGORX_VERSION")
#endif

[Setup]
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=AegorX Project
DefaultDirName={autopf}\AegorX
OutputBaseFilename=AegorXSetup-{#AppVersion}-windows-amd64
OutputDir=installer-out
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
Compression=lzma2
SolidCompression=yes
LicenseFile=..\LICENSE

[Files]
Source: "..\dist-standalone\aegorx.exe"; DestDir: "{app}"; DestName: "aegorx.exe"; Flags: ignoreversion

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop icon for the scanner console"; GroupDescription: "Additional icons:"

[Icons]
Name: "{autoprograms}\AegorX"; Filename: "{app}\aegorx.exe"
Name: "{autodesktop}\AegorX"; Filename: "{app}\aegorx.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\aegorx.exe"; Parameters: "--version"; Description: "Verify installation (prints version in a console window)"; Flags: postinstall skipifsilent unchecked
