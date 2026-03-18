"""Utilities for preparing and validating GREENWIRE's static distribution.

This module centralises the logic for assembling an offline build of the
distribution, including Python module mirroring, Java dependency discovery,
and CAP metadata inspection.  It replaces a collection of shell notes and
ad-hoc scripts with a single, testable entry point that can be driven by
automation or invoked manually by operators.

Key features
------------
* Declarative manifest describing the Python modules and Java artefacts that
  must be present in a static deployment.
* Helper for copying the live Python modules into ``static/lib`` so that a
  prepared package can execute without reaching back into the repository.
* CAP source analyser that scans every JavaCard applet and reports on
  instruction coverage, cryptographic features, and potential omissions.
* CLI exposing ``check`` (validate), ``prepare-python`` (mirror modules), and
  ``cap-report`` (JSON description of applet capabilities) sub-commands.

The unit tests exercise this module directly; ``verify_static.py`` simply
wraps the reporting functionality to present operator-friendly status output.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Sequence


# -- Static manifest -------------------------------------------------------


DEFAULT_MANIFEST: Dict[str, object] = {
    "python_modules": {
        "android_nfc.py": {
            "source": "modules/android_nfc.py",
            "description": "Android NFC transport helpers for offline use",
        },
        "emulation.py": {
            "source": "modules/emulation.py",
            "description": "Card and terminal emulation primitives",
        },
        "greenwire_crypto_fuzzer.py": {
            "source": "modules/greenwire_crypto_fuzzer.py",
            "description": "Cryptographic fuzzing harness mirrored for static runs",
        },
        "greenwire_emv_compliance.py": {
            "source": "modules/greenwire_emv_compliance.py",
            "description": "EMV compliance checks available offline",
        },
        "thales_emulator.py": {
            "source": "hsm/thales_emulator.py",
            "description": "Emulated HSM used for secure element rehearsals",
        },
    },
    "java_artifacts": {
        "ant-javacard.jar": {
            "path": "static/java/ant-javacard.jar",
            "external": True,
            "instructions": "Download ant-javacard.jar from the official "
            "repository and place it under static/java/.",
            "description": "Ant task definitions required for JavaCard CAP builds",
        },
        "gp.jar": {
            "path": "static/java/gp.jar",
            "external": True,
            "instructions": "Place GlobalPlatformPro's gp.jar under "
            "static/java/ to enable CAP deployment.",
            "description": "GlobalPlatformPro tooling used to load CAPs",
        },
        "api_classic.jar": {
            "path": "static/java/javacard_lib/api_classic.jar",
            "external": True,
            "instructions": "Copy the JavaCard SDK API jar to "
            "static/java/javacard_lib/",
            "description": "JavaCard SDK classes referenced during compilation",
        },
    },
    "required_directories": [
        "static",
        "static/java",
        "static/lib",
    ],
    "cap_source_roots": [
        "javacard/applet/src",
    ],
}


# -- Data classes ----------------------------------------------------------


@dataclass
class DependencyIssue:
    """Represents a missing dependency together with remediation advice."""

    name: str
    path: Path
    instructions: str | None = None

    def as_dict(self) -> Dict[str, str]:
        payload = {"name": self.name, "path": str(self.path)}
        if self.instructions:
            payload["instructions"] = self.instructions
        return payload


@dataclass
class CapMetadata:
    """Summarised view of a JavaCard applet source file."""

    source: Path
    class_name: str
    instructions: List[str] = field(default_factory=list)
    cla_values: List[str] = field(default_factory=list)
    aids: List[str] = field(default_factory=list)
    uses_owner_pin: bool = False
    uses_crypto: bool = False
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "source": str(self.source),
            "class_name": self.class_name,
            "instructions": self.instructions,
            "cla_values": self.cla_values,
            "aids": self.aids,
            "uses_owner_pin": self.uses_owner_pin,
            "uses_crypto": self.uses_crypto,
            "notes": self.notes,
        }

    @classmethod
    def from_source(cls, source: Path) -> "CapMetadata":
        text = source.read_text(encoding="utf-8", errors="ignore")

        class_match = re.search(
            r"class\s+(?P<cls>\w+)\s+extends\s+Applet", text
        )
        class_name = class_match.group("cls") if class_match else source.stem

        instruction_pattern = re.compile(
            r"static\s+final\s+byte\s+(?:INS_|INS)(?P<name>[A-Z0-9_]+)\s*=\s*"
            r"(?:\(byte\)\s*)?(?:0x(?P<hex>[0-9A-Fa-f]{1,2})|(?P<int>\d+))"
        )
        cla_pattern = re.compile(
            r"static\s+final\s+byte\s+CLA[_A-Z0-9]*\s*=\s*"
            r"(?:\(byte\)\s*)?(?:0x(?P<hex>[0-9A-Fa-f]{1,2})|(?P<int>\d+))"
        )
        aid_pattern = re.compile(
            r"0x[0-9A-Fa-f]{2}(?:\s*,\s*0x[0-9A-Fa-f]{2}){4,16}"
        )

        instructions = [
            match.group("name")
            for match in instruction_pattern.finditer(text)
        ]
        cla_values = [
            match.group("hex") or match.group("int")
            for match in cla_pattern.finditer(text)
        ]
        aids = [match.group(0).replace(" ", "") for match in aid_pattern.finditer(text)]

        uses_owner_pin = "OwnerPIN" in text
        uses_crypto = any(keyword in text for keyword in ("Signature", "Cipher", "KeyPair"))

        notes: List[str] = []
        if "process(" not in text:
            notes.append("process() implementation not found")
        if "install(" not in text:
            notes.append("install() method not present")
        if not instructions:
            notes.append("No INS constants detected")

        return cls(
            source=source,
            class_name=class_name,
            instructions=instructions,
            cla_values=cla_values,
            aids=aids,
            uses_owner_pin=uses_owner_pin,
            uses_crypto=uses_crypto,
            notes=notes,
        )


# -- Core distribution helper ----------------------------------------------


class StaticDistribution:
    """Encapsulates static build checks for the repository."""

    def __init__(self, root: Path | str | None = None, manifest: Dict[str, object] | None = None):
        self.root = Path(root) if root is not None else Path.cwd()
        self.manifest = manifest or DEFAULT_MANIFEST

    # -- Convenience paths -------------------------------------------------

    @property
    def static_dir(self) -> Path:
        return self.root / "static"

    @property
    def static_lib_dir(self) -> Path:
        return self.static_dir / "lib"

    # -- Discovery ---------------------------------------------------------

    def _expected_python_targets(self) -> Dict[str, Path]:
        targets: Dict[str, Path] = {}
        for filename in self.manifest.get("python_modules", {}):
            targets[filename] = self.static_lib_dir / filename
        return targets

    def _python_sources(self) -> Dict[str, Path]:
        sources: Dict[str, Path] = {}
        manifest_entries: Dict[str, Dict[str, str]] = self.manifest.get(
            "python_modules", {}
        )
        for filename, metadata in manifest_entries.items():
            sources[filename] = self.root / metadata["source"]
        return sources

    def _java_artifacts(self) -> Dict[str, Dict[str, object]]:
        payload: Dict[str, Dict[str, object]] = {}
        manifest_entries: Dict[str, Dict[str, object]] = self.manifest.get(
            "java_artifacts", {}
        )
        for name, metadata in manifest_entries.items():
            entry = dict(metadata)
            entry["path"] = self.root / metadata["path"]
            payload[name] = entry
        return payload

    def cap_source_files(self) -> List[Path]:
        roots = [self.root / rel for rel in self.manifest.get("cap_source_roots", [])]
        results: List[Path] = []
        for root in roots:
            if not root.exists():
                continue
            for path in root.rglob("*.java"):
                if "test" in path.parts:
                    continue
                results.append(path)
        return results

    # -- Checks ------------------------------------------------------------

    def check_required_directories(self) -> List[DependencyIssue]:
        issues: List[DependencyIssue] = []
        for rel_path in self.manifest.get("required_directories", []):
            path = self.root / rel_path
            if not path.exists():
                issues.append(DependencyIssue(rel_path, path, "Create the directory."))
        return issues

    def check_python_bundle(self) -> List[DependencyIssue]:
        issues: List[DependencyIssue] = []
        targets = self._expected_python_targets()
        for filename, path in targets.items():
            if not path.exists():
                issues.append(
                    DependencyIssue(
                        filename,
                        path,
                        "Run `python -m tools.static_distribution prepare-python`",
                    )
                )
        return issues

    def check_java_bundle(self) -> List[DependencyIssue]:
        issues: List[DependencyIssue] = []
        for name, metadata in self._java_artifacts().items():
            path: Path = metadata["path"]
            if path.exists():
                continue
            instructions = metadata.get("instructions")
            issues.append(DependencyIssue(name, path, instructions))
        return issues

    def collect_cap_metadata(self) -> List[CapMetadata]:
        return [CapMetadata.from_source(path) for path in self.cap_source_files()]

    def validate_cap_sources(self) -> List[DependencyIssue]:
        issues: List[DependencyIssue] = []
        for metadata in self.collect_cap_metadata():
            for note in metadata.notes:
                issues.append(
                    DependencyIssue(
                        metadata.class_name,
                        metadata.source,
                        note,
                    )
                )
        return issues

    # -- Actions -----------------------------------------------------------

    def prepare_python_bundle(self, overwrite: bool = False) -> None:
        self.static_lib_dir.mkdir(parents=True, exist_ok=True)
        sources = self._python_sources()
        targets = self._expected_python_targets()

        # Ensure the package directory is a proper module
        init_file = self.static_lib_dir / "__init__.py"
        if overwrite or not init_file.exists():
            init_file.write_text('"""Make static.lib behave like a package."""\n')

        for filename, src_path in sources.items():
            dest_path = targets[filename]
            if dest_path.exists() and not overwrite:
                continue
            if not src_path.exists():
                raise FileNotFoundError(f"Source module missing: {src_path}")
            shutil.copy2(src_path, dest_path)

    # -- Reporting ---------------------------------------------------------

    def generate_report(self) -> Dict[str, object]:
        directories = self.check_required_directories()
        python_missing = self.check_python_bundle()
        java_missing = self.check_java_bundle()
        cap_metadata = self.collect_cap_metadata()
        cap_issues = self.validate_cap_sources()

        return {
            "directory_issues": [issue.as_dict() for issue in directories],
            "python_missing": [issue.as_dict() for issue in python_missing],
            "java_missing": [issue.as_dict() for issue in java_missing],
            "cap_issues": [issue.as_dict() for issue in cap_issues],
            "cap_metadata": [entry.to_dict() for entry in cap_metadata],
        }

    # -- Inventory --------------------------------------------------------

    def _manifest_descriptions(self) -> Dict[Path, str]:
        mapping: Dict[Path, str] = {}
        for filename, metadata in self.manifest.get("python_modules", {}).items():
            description = metadata.get("description", "Python module")
            mapping[self.static_lib_dir / filename] = description

        for metadata in self._java_artifacts().values():
            description = metadata.get("description", "Java dependency")
            mapping[metadata["path"]] = description

        return mapping

    def build_inventory(self) -> List[Dict[str, object]]:
        """Summarise every file shipped in the static distribution."""

        descriptions = self._manifest_descriptions()
        inventory: List[Dict[str, object]] = []

        # Enumerate files under static/
        for path in sorted(self.static_dir.rglob("*")):
            if not path.is_file():
                continue

            rel_path = path.relative_to(self.root)
            description = descriptions.get(path)
            if description is None:
                if path.suffix in {".jar", ".cap"}:
                    description = "Java archive"
                elif path.suffix in {".py", ".pyc"}:
                    description = "Python module"
                else:
                    description = f"Static asset ({path.suffix or 'no extension'})"

            inventory.append(
                {
                    "path": rel_path.as_posix(),
                    "size_bytes": path.stat().st_size,
                    "description": description,
                    "status": "present",
                }
            )

        # Include manifest entries that are missing on disk.
        for target, description in descriptions.items():
            if target.exists():
                continue
            rel_path = target.relative_to(self.root)
            inventory.append(
                {
                    "path": rel_path.as_posix(),
                    "size_bytes": 0,
                    "description": description,
                    "status": "missing",
                }
            )

        inventory.sort(key=lambda entry: entry["path"])
        return inventory

    def render_inventory_markdown(self, inventory: List[Dict[str, object]] | None = None) -> str:
        """Render the static distribution inventory as a Markdown table."""

        entries = inventory or self.build_inventory()
        lines = [
            "# Static Distribution Inventory",
            "",
            "| Path | Size | Status | Description |",
            "| --- | ---: | --- | --- |",
        ]

        for entry in entries:
            size = entry["size_bytes"]
            if size >= 1024:
                human = f"{size / 1024:.1f} KiB"
            else:
                human = f"{size} B"
            lines.append(
                "| {path} | {size} ({human}) | {status} | {desc} |".format(
                    path=entry["path"],
                    size=size,
                    human=human,
                    status=entry["status"],
                    desc=entry["description"],
                )
            )

        lines.append("")
        return "\n".join(lines)


# -- CLI -------------------------------------------------------------------


def _cmd_check(args: argparse.Namespace) -> int:
    dist = StaticDistribution(Path(args.root))
    report = dist.generate_report()
    print(json.dumps(report, indent=2, sort_keys=True))

    issue_count = sum(
        len(report[key])
        for key in ("directory_issues", "python_missing", "java_missing", "cap_issues")
    )
    return 0 if issue_count == 0 else 1


def _cmd_prepare_python(args: argparse.Namespace) -> int:
    dist = StaticDistribution(Path(args.root))
    dist.prepare_python_bundle(overwrite=args.overwrite)
    print("Static Python modules mirrored under static/lib")
    return 0


def _cmd_cap_report(args: argparse.Namespace) -> int:
    dist = StaticDistribution(Path(args.root))
    metadata = [entry.to_dict() for entry in dist.collect_cap_metadata()]
    print(json.dumps(metadata, indent=2, sort_keys=True))
    return 0


def _cmd_inventory(args: argparse.Namespace) -> int:
    dist = StaticDistribution(Path(args.root))
    inventory = dist.build_inventory()
    markdown = dist.render_inventory_markdown(inventory)
    output_path = Path(args.output)
    output_path.write_text(markdown, encoding="utf-8")
    print(f"Inventory written to {output_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare and validate GREENWIRE's static distribution"
    )
    parser.add_argument(
        "--root",
        type=str,
        default=str(Path.cwd()),
        help="Repository root (defaults to current working directory)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    parser_check = subparsers.add_parser("check", help="Report static build status")
    parser_check.set_defaults(func=_cmd_check)

    parser_prepare = subparsers.add_parser(
        "prepare-python", help="Mirror Python modules into static/lib"
    )
    parser_prepare.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing mirrored modules",
    )
    parser_prepare.set_defaults(func=_cmd_prepare_python)

    parser_cap = subparsers.add_parser(
        "cap-report", help="Describe JavaCard applet capabilities"
    )
    parser_cap.set_defaults(func=_cmd_cap_report)

    parser_inventory = subparsers.add_parser(
        "inventory",
        help="Document every static distribution asset in Markdown",
    )
    parser_inventory.add_argument(
        "--output",
        default="STATIC_DISTRIBUTION_INVENTORY.md",
        help="Path to write the Markdown inventory",
    )
    parser_inventory.set_defaults(func=_cmd_inventory)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
