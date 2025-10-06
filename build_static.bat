@echo off
REM GREENWIRE Static Build Script - Self-contained deployment
REM Creates fully static build with all dependencies bundled

echo GREENWIRE Static Build - Creating Self-Contained Deployment
echo =========================================================

set STATIC_JAVA_HOME=static\java\jdk\jdk8u462-b08
set STATIC_ANT_HOME=static\java\apache-ant-1.10.15
set JAVACARD_LIB=static\java\javacard_lib
set PATH=%STATIC_JAVA_HOME%\bin;%STATIC_ANT_HOME%\bin;%PATH%

echo.
echo 1. Verifying static Java environment...
if not exist "%STATIC_JAVA_HOME%\bin\javac.exe" (
    echo ERROR: Static JDK not found at %STATIC_JAVA_HOME%
    echo Extracting bundled JDK...
    cd static\java
    if exist temurin8.zip (
        powershell -command "Expand-Archive -Path temurin8.zip -DestinationPath jdk -Force"
        cd ..\..
    ) else (
        echo ERROR: temurin8.zip not found
        pause
        exit /b 1
    )
)

echo.
echo 2. Creating build directories...
mkdir build 2>nul
mkdir build\static 2>nul
mkdir build\static\java 2>nul
mkdir build\static\lib 2>nul

echo.
echo 3. Compiling with static Java...
"%STATIC_JAVA_HOME%\bin\javac" CommandAPDU.java
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Standard Java compilation failed
    pause
    exit /b 1
)

echo.
echo 4. Compiling JavaCard applets with static classpath...
"%STATIC_JAVA_HOME%\bin\javac" -cp "%JAVACARD_LIB%\api_classic.jar" -d build caplets\merchant_probes\*.java
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Merchant probes compilation failed
    pause
    exit /b 1
)

"%STATIC_JAVA_HOME%\bin\javac" -cp "%JAVACARD_LIB%\api_classic.jar" -d build applets\emv_vulntests\*.java
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: EMV vulnerability testers compilation failed
    pause
    exit /b 1
)

"%STATIC_JAVA_HOME%\bin\javac" -cp "%JAVACARD_LIB%\api_classic.jar" -d build javacard\applet\src\com\greenwire\*.java
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Main applets compilation failed
    pause
    exit /b 1
)

echo.
echo 5. Copying static dependencies...
xcopy /E /I /Y static\java\javacard_lib build\static\java\javacard_lib
xcopy /E /I /Y static\java\*.jar build\static\java\
xcopy /E /I /Y static\lib build\static\lib
xcopy /E /I /Y lib\*.jar build\static\java\

echo.
echo 6. Creating static runtime scripts...
echo @echo off > build\compile_static.bat
echo set JAVACARD_LIB=static\java\javacard_lib >> build\compile_static.bat
echo javac -cp "%%JAVACARD_LIB%%\api_classic.jar" -d . *.java >> build\compile_static.bat

echo #!/bin/bash > build/compile_static.sh
echo JAVACARD_LIB=static/java/javacard_lib >> build/compile_static.sh
echo javac -cp "\$JAVACARD_LIB/api_classic.jar" -d . *.java >> build/compile_static.sh
chmod +x build/compile_static.sh

echo.
echo 7. Creating CAP file generation script...
echo @echo off > build\generate_cap.bat
echo java -jar static\java\ant-javacard.jar -noverify -cap %%1.cap -out . %%1 >> build\generate_cap.bat

echo.
echo 8. Creating deployment script...
echo @echo off > build\deploy_cap.bat
echo java -jar static\java\gp.jar --install %%1 --verbose >> build\deploy_cap.bat

echo.
echo ========================================
echo SUCCESS: Static build completed!
echo ========================================
echo.
echo Static build contents:
echo - All Java classes compiled with bundled JDK
echo - JavaCard API libraries included
echo - GlobalPlatformPro for deployment
echo - ant-javacard for CAP generation
echo - No external dependencies required
echo.
echo Usage:
echo   cd build
echo   compile_static.bat [additional_files.java]
echo   generate_cap.bat [applet_name]
echo   deploy_cap.bat [applet.cap]
echo.
echo The build directory is now self-contained!

pause