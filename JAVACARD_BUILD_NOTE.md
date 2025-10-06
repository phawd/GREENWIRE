# Java Card build notes

This repository contains Java Card source files under `GREENWIRE/` that require the Java Card SDK to compile into `.cap` files.

Common issues seen when opening these files in a regular JDK project:

- The `javacard.framework.*` packages are not available to a standard JDK. You must install and point your build to a Java Card SDK (JC_HOME or similar).
- IDE compile errors (cannot find symbol: Applet, APDU, ISO7816, etc.) are expected unless the Java Card libraries are on the project's classpath.

How to build Java Card applets locally (high level):

1. Install Java 8 or the JDK version supported by your Java Card SDK.
2. Download and unpack the Java Card SDK (Oracle Java Card, or other compatible SDK).
3. Set environment variable `JC_HOME` to the SDK root.
4. Use `ant` or the bundled `ant-javacard` scripts in this repo to build CAP files. Example (on Unix):

   export JC_HOME=/path/to/javacard_sdk
   cd GREENWIRE
   ant -f ant-javacard/build.xml

If you need, I can add a lightweight Gradle/Ant wrapper and CI job that builds Java Card CAP files inside a container that has the Java Card SDK installed. Note: Java Card SDK redistribution is restricted, so CI must either download it from an approved location or use a preinstalled image.
