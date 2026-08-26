; Defentra Windows installer (Inno Setup 6)
; Built by CI: ISCC packaging/windows-installer.iss
; The .exe installed here is the PyInstaller standalone build.

#define AppName "Defentra"
#ifndef AppVersion
#define AppVersion GetEnv("DEFENTRA_VERSION")
#endif

[Setup]
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=Defentra Project
DefaultDirName={autopf}\Defentra
OutputBaseFilename=DefentraSetup-{#AppVersion}-windows-amd64
OutputDir=installer-out
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
Compression=lzma2
SolidCompression=yes
LicenseFile=..\..\LICENSE

[Files]
Source: "..\..\dist-standalone\defentra.exe"; DestDir: "{app}"; DestName: "defentra.exe"; Flags: ignoreversion

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop icon for the scanner console"; GroupDescription: "Additional icons:"

[Icons]
Name: "{autoprograms}\Defentra"; Filename: "{app}\defentra.exe"
Name: "{autodesktop}\Defentra"; Filename: "{app}\defentra.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\defentra.exe"; Parameters: "--version"; Description: "Verify installation (prints version in a console window)"; Flags: postinstall skipifsilent unchecked
