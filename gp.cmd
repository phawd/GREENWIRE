@echo off
setlocal
set JAR=%~dp0static\java\gp.jar
if not exist "%JAR%" (
  echo gp.jar not found at %JAR%
  exit /b 1
)
set JDKDIR=
for /d %%D in ("%~dp0static\java\jdk\jdk*") do set JDKDIR=%%D
if exist "%JDKDIR%\bin\java.exe" (
  set JAVAEXE="%JDKDIR%\bin\java.exe"
) else (
  set JAVAEXE=java
)
%JAVAEXE% -jar "%JAR%" %*