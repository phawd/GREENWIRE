# JavaCard Offline Setup and Required Artifacts

This document explains the minimal artifacts required to perform offline JavaCard CAP conversion and deployment using the GREENWIRE repository's Gradle tasks.

Required files (not distributable in many cases due to vendor licenses):

- sdk/javacard/lib/tools.jar
  - JavaCard converter runtime provided by the Oracle/Classic JavaCard SDK.
  - Place the file at `GREENWIRE/sdk/javacard/lib/tools.jar` inside the static bundle (or repo) so `gradle convertCap` can find it.

- sdk/javacard/api_export_files/...
  - The `.exp` API export descriptors from the JavaCard SDK. They are usually under `api_export_files` in the SDK.

- lib/GlobalPlatformPro.jar
  - GlobalPlatformPro fat JAR used by the `deployCap` Gradle tasks. Place it at `lib/GlobalPlatformPro.jar`.

Optional helper jars:

- static/java/ant-javacard.jar
  - A standalone tool that can build CAPs without the full SDK in some cases; present in the repository's static/java directory.

How to obtain and place artifacts:

1. Download the Oracle JavaCard Classic SDK matching your target (check licensing before distribution).
2. Copy `tools.jar` and the `api_export_files` directory into `GREENWIRE/sdk/javacard/lib` and `GREENWIRE/sdk/javacard/api_export_files` respectively.
3. Obtain GlobalPlatformPro from its project page or build from source; place the resulting `GlobalPlatformPro.jar` into `GREENWIRE/lib/`.

Note on licensing: The JavaCard SDK and GlobalPlatformPro may have license terms that prevent redistribution. For static bundles intended for public distribution, prefer documenting how to obtain these artifacts rather than bundling them.

Troubleshooting:

- If `convertCap` fails with a message about `tools.jar` or export files, verify the exact paths listed above.
- If `deployCap` fails, ensure your smartcard reader is connected and `lib/GlobalPlatformPro.jar` exists.

If you want, I can prepare a small powershell script to fetch and place these artifacts into the right locations (interactive steps will still be required for credentials/licensing).
