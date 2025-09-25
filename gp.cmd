@echo off
setlocal
set JAR=%~dp0static\java\gp.jar
if not exist "%JAR%" (
  echo gp.jar not found at %JAR%
  exit /b 1
)
java -jar "%JAR%" %*