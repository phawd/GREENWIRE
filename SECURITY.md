
# GREENWIRE Security Policy & Field/Production Best Practices

## CA Key/Certificate Handling

- Always store CA keys/certificates in `ca_keys.json` and restrict access to trusted operators only.
- Never share private CA keys or production certificates outside of secure channels.
- For field/production use, validate your CA key/cert before issuing or installing cards (see README.md for validation steps).
- Rotate CA keys/certs regularly and audit usage logs for unauthorized access.

## Field/Production Testing

- Only use the `--hardware` and `--profile` options with trusted, physically secured readers.
- Always log issuance and field operations with `--csv-output` for compliance and audit.
- For contactless/NFC operations, ensure hardware is physically secured and firmware is up to date.

## Operator Safety

- Do not use GREENWIRE for unauthorized card issuance or testing.
- Follow all local laws and industry regulations regarding smartcard/EMV testing.
- Report any security issues or vulnerabilities to the project maintainers.

## Reporting Security Issues

If you discover a security vulnerability, please report it via GitHub Issues or contact the maintainers directly. Do not disclose sensitive details publicly until a fix is available.
