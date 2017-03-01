echo off
echo.
echo Checking up environment...
set QT_INSTALL_DIR=C:\app\Qt\Qt5.7.0-msvc2013\5.7\msvc2013
set QML_IMPORT_PATH=%QT_INSTALL_DIR%\qml
set PATH=%QT_INSTALL_DIR%\bin;%PATH%
set VCINSTALLDIR=C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC
cd /D %QT_INSTALL_DIR%

:Getting BAT run directory
cd /d %~dp0
set BAT_FILE_DIR=%cd%

echo.
echo Starting to deploy....
echo.

:if "%1" == "h" goto begin 
:mshta vbscript:createobject("wscript.shell").run("""%~fnx0"" h",0)(window.close)&&exit 
:begin

windeployqt WSAnaKit.exe --qmldir %QML_IMPORT_PATH%

: delete Material Folders
rmdir /q /s %BAT_FILE_DIR%\Material
rmdir /q /s %BAT_FILE_DIR%\XjQmlUi
echo d | xcopy /e /y %QML_IMPORT_PATH%\Material %BAT_FILE_DIR%\Material
echo d | xcopy /e /y %QML_IMPORT_PATH%\XjQmlUi %BAT_FILE_DIR%\XjQmlUi
