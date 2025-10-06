"""
merge_imports.py

Scans Python files under a path and:
 - merges duplicate top-level imports into a single import per module
 - marks lines with unused imports with "# noqa: F401" so they remain "live"

Default mode is dry-run: it prints proposed changes. Use --apply to modify files.

This tool is conservative:
 - only processes top-level import statements (no imports inside functions/classes)
 - it never removes imports; unused names are preserved but a noqa comment is added
 - it preserves aliases and avoids modifying indented imports

Usage:
    python tools/merge_imports.py --path ./GREENWIRE --apply

"""
from __future__ import annotations

import argparse
import ast
import os
import re
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Iterable

IMPORT_RE = re.compile(r"^\s*(from\s+|import\s+)")


def find_py_files(root: str, exclude_dirs: Iterable[str] | None = None) -> List[str]:
    exclude_dirs = set(exclude_dirs or ["__pycache__", ".git"])
    out: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # skip excluded directories
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        for fn in filenames:
            if fn.endswith(".py"):
                out.append(os.path.join(dirpath, fn))
    return out


def is_top_level_import_line(line: str) -> bool:
    # A conservative test: line must start with 'from ' or 'import ' with no leading indent
    return bool(re.match(r"^(from|import)\s+", line))


class FileImportChanges:
    def __init__(self, path: str):
        self.path = path
        self.original: str = ""
        self.lines: List[str] = []
        # store import node info: list of dicts with node type, module, level, names, lineno, end_lineno
        self.import_nodes: List[dict] = []
        self.used_names: set[str] = set()
        self.proposed: str = ""

    def load(self) -> None:
        with open(self.path, "r", encoding="utf-8") as f:
            self.original = f.read()
        self.lines = self.original.splitlines()

    def analyze(self) -> None:
        # parse AST to determine used names and collect top-level import nodes (with ranges)
        try:
            tree = ast.parse(self.original, filename=self.path)
        except SyntaxError:
            # skip files with syntax errors
            return

        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                self.used_names.add(node.id)

        # collect top-level import and import-from nodes with their full span (lineno..end_lineno)
        for node in tree.body:
            if isinstance(node, ast.Import):
                infos = []
                for alias in node.names:
                    infos.append((alias.name, alias.asname))
                self.import_nodes.append({
                    "type": "import",
                    "module": None,
                    "level": 0,
                    "names": infos,
                    "lineno": node.lineno - 1,
                    "end_lineno": getattr(node, "end_lineno", node.lineno) - 1,
                })
            elif isinstance(node, ast.ImportFrom):
                infos = []
                for alias in node.names:
                    infos.append((alias.name, alias.asname))
                self.import_nodes.append({
                    "type": "from",
                    "module": node.module or "",
                    "level": node.level or 0,
                    "names": infos,
                    "lineno": node.lineno - 1,
                    "end_lineno": getattr(node, "end_lineno", node.lineno) - 1,
                })

    def build_proposal(self, safe_only: bool = True) -> None:
        # Build a conservative proposal using collected import nodes
        if not self.import_nodes:
            self.proposed = self.original
            return

        edits: Dict[int, Optional[str]] = {}

        # Group from-imports by (module, level)
        from_groups: Dict[Tuple[str, int], List[dict]] = defaultdict(list)
        simple_imports: List[dict] = []
        for node in self.import_nodes:
            if node["type"] == "from":
                # skip star imports entirely from merging
                if any(name == "*" for name, _ in node["names"]):
                    continue
                from_groups[(node["module"], node["level"])].append(node)
            else:
                simple_imports.append(node)

        # Process from-import groups conservatively
        for (module, level), nodes in from_groups.items():
            # collect unique (name, asname) preserving asname uniqueness
            unique: Dict[Tuple[str, Optional[str]], dict] = {}
            linenos: List[int] = []
            all_used = True
            for n in nodes:
                linenos.append(n["lineno"])  # starting lineno for node
                for nm, asn in n["names"]:
                    unique[(nm, asn)] = {"name": nm, "asname": asn}
                    test_name = asn if asn else nm
                    if test_name not in self.used_names:
                        all_used = False
            linenos = sorted(set(linenos))
            first_lineno = linenos[0]
            name_parts = []
            for nm, asn in sorted(((v["name"], v["asname"]) for v in unique.values()), key=lambda x: x[0]):
                if asn:
                    name_parts.append(f"{nm} as {asn}")
                else:
                    name_parts.append(nm)
            level_dots = "." * level
            module_str = f"{level_dots}{module}" if module else level_dots or ""
            import_text = f"from {module_str} import {', '.join(name_parts)}"
            if not all_used:
                import_text += "  # noqa: F401"

            # Conservative: only merge from-imports if safe_only is False or none of the nodes span comments/complex formatting
            dangerous = False
            if safe_only:
                # detect if any original block contains comments inline or spans multiple non-contiguous lines
                for n in nodes:
                    span_lines = self.lines[n["lineno"] : n["end_lineno"] + 1]
                    for l in span_lines:
                        if "#" in l and not l.strip().startswith("#"):
                            dangerous = True
                            break
                    if dangerous:
                        break
            if dangerous and safe_only:
                # skip merging: leave originals intact
                continue

            # mark non-first nodes for removal and replace first with merged import
            for n in nodes[1:]:
                # clear full span
                for ln in range(n["lineno"], n["end_lineno"] + 1):
                    edits[ln] = ""
            # replace first node's span with merged import (preserve trailing newline semantics later)
            first_node = nodes[0]
            # clear its full span and set replacement at its starting lineno
            for ln in range(first_node["lineno"], first_node["end_lineno"] + 1):
                edits[ln] = ""
            edits[first_node["lineno"]] = import_text

        # Process simple imports: merge all simple imports into one import statement at first simple import location
        if simple_imports:
            # Build list of all (name, asname) across simple imports
            infos: List[Tuple[str, Optional[str], int, int]] = []
            for n in simple_imports:
                for nm, asn in n["names"]:
                    infos.append((nm, asn, n["lineno"], n["end_lineno"]))
            # detect duplicates and unique names
            seen = {}
            all_used = True
            entries = []
            for nm, asn, ln, end_ln in sorted(infos, key=lambda x: (x[2], x[0])):
                key = (nm, asn)
                if key in seen:
                    continue
                seen[key] = True
                entries.append((nm, asn, ln, end_ln))
                test_name = asn if asn else nm
                if test_name not in self.used_names:
                    all_used = False
            if entries:
                first_lineno = entries[0][2]
                name_parts = []
                for nm, asn, _, _ in entries:
                    if asn:
                        name_parts.append(f"{nm} as {asn}")
                    else:
                        name_parts.append(nm)
                import_text = f"import {', '.join(sorted(name_parts))}"
                if not all_used:
                    import_text += "  # noqa: F401"

                # Conservative safe-only checks: avoid merging if any original span contained inline comments
                dangerous = False
                if safe_only:
                    for _, _, ln, end_ln in entries:
                        for l in self.lines[ln:end_ln + 1]:
                            if "#" in l and not l.strip().startswith("#"):
                                dangerous = True
                                break
                        if dangerous:
                            break
                if not dangerous or not safe_only:
                    # remove all original simple import spans
                    for _, _, ln, end_ln in entries[1:]:
                        for ln_rm in range(ln, end_ln + 1):
                            edits[ln_rm] = ""
                    # replace first span with merged import
                    first_entry = entries[0]
                    for ln_rm in range(first_entry[2], first_entry[3] + 1):
                        edits[ln_rm] = ""
                    edits[first_entry[2]] = import_text

        # If no edits were decided, keep original
        if not edits:
            self.proposed = self.original
            return

        # Apply edits preserving other lines
        out_lines: List[str] = []
        idx = 0
        total = len(self.lines)
        while idx < total:
            if idx in edits:
                rep = edits[idx]
                if rep:
                    out_lines.append(rep)
                # Skip to next line
                idx += 1
            else:
                out_lines.append(self.lines[idx])
                idx += 1

        self.proposed = "\n".join(out_lines) + ("\n" if self.original.endswith("\n") else "")

    def changed(self) -> bool:
        return self.proposed != self.original

    def apply(self) -> None:
        if not self.changed():
            return
        backup = self.path + ".bak"
        if not os.path.exists(backup):
            with open(backup, "w", encoding="utf-8") as f:
                f.write(self.original)
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(self.proposed)


def process_file(path: str, apply: bool = False) -> Tuple[bool, str]:
    fic = FileImportChanges(path)
    fic.load()
    fic.analyze()
    fic.build_proposal()
    if fic.changed():
        summary = f"Changes for {path}:\n"
        summary += "--- original excerpt ---\n"
        summary += "\n".join(fic.lines[max(0, 0):min(len(fic.lines), 50)]) + "\n"
        summary += "--- proposed excerpt ---\n"
        summary += "\n".join(fic.proposed.splitlines()[:50]) + "\n"
        if apply:
            fic.apply()
            summary += "(applied)\n"
        else:
            summary += "(dry-run)\n"
        return True, summary
    else:
        return False, ""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", default=".", help="Root path to scan (default: .)")
    parser.add_argument("--apply", action="store_true", help="Apply changes to files")
    parser.add_argument("--exclude", nargs="*", default=None, help="Directories to exclude")
    parser.add_argument("--report", default=None, help="Write report to a file")
    parser.add_argument("--safe-only", action="store_true", help="Only perform conservative merges (avoid blocks with inline comments or star imports)")
    args = parser.parse_args()

    exclude = args.exclude or ['__pycache__', '.git', 'build', 'dist', 'java']

    py_files = find_py_files(args.path, exclude_dirs=exclude)
    py_files = [p for p in py_files if os.path.abspath(p) != os.path.abspath(__file__)]
    changed_any = False
    reports: List[str] = []
    for p in sorted(py_files):
        fic = FileImportChanges(p)
        fic.load()
        fic.analyze()
        fic.build_proposal(safe_only=args.safe_only)
        if fic.changed():
            changed_any = True
            summary = f"Changes for {p}:\n"
            summary += "--- original excerpt ---\n"
            summary += "\n".join(fic.lines[:50]) + "\n"
            summary += "--- proposed excerpt ---\n"
            summary += "\n".join(fic.proposed.splitlines()[:50]) + "\n"
            if args.apply:
                fic.apply()
                summary += "(applied)\n"
            else:
                summary += "(dry-run)\n"
            reports.append(summary)

    out = []
    if not reports:
        out.append("No import merges or unused import markings proposed.")
    else:
        out.append(f"Proposed changes in {len(reports)} files:\n")
        out.extend(reports)

    out_text = "\n".join(out)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(out_text)
    print(out_text)


if __name__ == "__main__":
    main()
