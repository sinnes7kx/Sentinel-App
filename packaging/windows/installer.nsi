Target amd64-unicode
Unicode true
!include "MUI2.nsh"
!include "x64.nsh"
Name "Sentinel"
OutFile "${OUTPUT}"
InstallDir "$LOCALAPPDATA\Programs\Sentinel"
RequestExecutionLevel user
SetCompressor zlib
SetDatablockOptimize on
!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchSentinel
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Function .onInit
  ${IfNot} ${IsNativeAMD64}
    MessageBox MB_ICONSTOP "This Sentinel build requires 64-bit Windows on an Intel or AMD processor."
    Abort
  ${EndIf}
FunctionEnd

Function LaunchSentinel
  Exec '"$INSTDIR\python\pythonw.exe" -E -s -B "$INSTDIR\run.py" --desktop'
FunctionEnd

Section "Sentinel"
  SetOutPath "$INSTDIR"
  File /r "${STAGE}/*"
  CreateShortcut "$SMPROGRAMS\Sentinel.lnk" "$INSTDIR\python\pythonw.exe" '-E -s -B "$INSTDIR\run.py" --desktop'
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelDesktop" "DisplayName" "Sentinel"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelDesktop" "UninstallString" '"$INSTDIR\Uninstall.exe"'
SectionEnd

Section "Uninstall"
  Delete "$SMPROGRAMS\Sentinel.lnk"
  !include "${UNINSTALL_FILES}"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelDesktop"
SectionEnd
