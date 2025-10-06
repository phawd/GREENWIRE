EMV CLI and JavaCard build notes

- Use `tools/emv_cli.py` for programmatic CA/key issuance and test artifact generation.
  Example:
    python tools/emv_cli.py gen-root --out-dir ca --common-name "Greenwire Root CA"

- JavaCard converter:
  The Gradle script `javacard/applet/build.gradle` now aggregates all JARs from
  `sdk/javacard/lib` onto the converter classpath and attempts to detect the
  right converter main class inside `tools.jar`.

  If conversion fails with ClassNotFound, ensure your `sdk/javacard/lib` contains
  a valid JavaCard SDK `tools.jar` matching the converter version (e.g., jc305, jc320),
  or use the bundled `ant-javacard.jar` fallback:

    java -jar static/java/ant-javacard.jar -src javacard/applet/src -out javacard/applet/build/cap ...

- Requirements: Python `cryptography` package for EMV helpers.
  Install: pip install cryptography
