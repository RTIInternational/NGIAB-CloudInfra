#!/usr/bin/env python3

from __future__ import annotations

import json
import shutil
import sqlite3
import sys
import ctypes
from pathlib import Path

import yaml

from pymodsim import PyModsimModel


def _log(message: str) -> None:
    print(f"[modsim-smoke] {message}")


def _fail(message: str, scratch_dir: Path | None = None) -> int:
    print(f"[modsim-smoke] FAIL: {message}", file=sys.stderr)
    if scratch_dir is not None:
        print(f"[modsim-smoke] Scratch directory preserved at {scratch_dir}", file=sys.stderr)
    return 1


def _resolve_run_relative(run_root: Path, raw_path: str) -> Path:
    path = Path(raw_path)
    return path if path.is_absolute() else (run_root / path).resolve()


def _classify_binary(path: Path) -> str:
    if not path.exists():
        return "missing"

    try:
        header = path.read_bytes()[:4]
    except Exception as exc:
        return f"unreadable: {exc}"

    if header[:2] == b"MZ":
        return "PE/Windows"
    if header == b"\x7fELF":
        return "ELF/Linux"
    return f"unknown ({header!r})"


def _can_load_managed_assembly(path: Path) -> str:
    try:
        import clr  # noqa: F401
        from System.Reflection import Assembly

        asm = Assembly.LoadFile(str(path))
        return f"ok ({asm.GetName().Name})"
    except Exception as exc:
        return f"fail ({type(exc).__name__}: {exc})"


def _can_load_native_library(path: Path) -> str:
    try:
        ctypes.CDLL(str(path))
        return "ok"
    except Exception as exc:
        return f"fail ({type(exc).__name__}: {exc})"


def _runtime_loadability_checks(dll_root: Path) -> list[str]:
    lines: list[str] = []

    dll_files = sorted(p for p in dll_root.rglob("*.dll") if p.is_file())
    so_files = sorted(p for p in dll_root.rglob("*.so") if p.is_file())

    class_counts = {
        "PE/Windows": 0,
        "ELF/Linux": 0,
        "unknown": 0,
        "missing": 0,
        "unreadable": 0,
    }

    managed_ok = 0
    managed_fail = 0
    native_ok = 0
    native_fail = 0
    native_skipped = 0

    flags: list[str] = []

    def _track_classification(value: str) -> None:
        if value in class_counts:
            class_counts[value] += 1
        elif value.startswith("unknown"):
            class_counts["unknown"] += 1
        elif value.startswith("unreadable"):
            class_counts["unreadable"] += 1
        else:
            class_counts["unknown"] += 1

    for p in dll_files:
        rel = p.relative_to(dll_root)
        classification = _classify_binary(p)
        _track_classification(classification)
        managed_status = _can_load_managed_assembly(p)
        if managed_status.startswith("ok"):
            managed_ok += 1
        else:
            managed_fail += 1
            flags.append(f"managed load failed: {rel} -> {managed_status}")

        # Only attempt native loading for ELF binaries on Linux.
        native_status = "skipped (not ELF)"
        if classification == "ELF/Linux":
            native_status = _can_load_native_library(p)
            if native_status == "ok":
                native_ok += 1
            else:
                native_fail += 1
                flags.append(f"native load failed: {rel} -> {native_status}")
        else:
            native_skipped += 1

    for p in so_files:
        rel = p.relative_to(dll_root)
        classification = _classify_binary(p)
        _track_classification(classification)
        native_status = _can_load_native_library(p)
        if native_status == "ok":
            native_ok += 1
        else:
            native_fail += 1
            flags.append(f"native load failed: {rel} -> {native_status}")

    if not dll_files and not so_files:
        return ["Interop audit: no *.dll or *.so artifacts found in pymodsim/dlls."]

    lines.append(
        f"Interop audit: scanned {len(dll_files) + len(so_files)} artifacts ({len(dll_files)} dll, {len(so_files)} so)."
    )
    lines.append(
        "Artifact classes: "
        f"PE/Windows={class_counts['PE/Windows']}, "
        f"ELF/Linux={class_counts['ELF/Linux']}, "
        f"unknown={class_counts['unknown']}, "
        f"unreadable={class_counts['unreadable']}."
    )
    lines.append(f"Managed assembly load checks (.dll): ok={managed_ok}, fail={managed_fail}.")
    lines.append(
        "Native load checks (ctypes): "
        f"ok={native_ok}, fail={native_fail}, skipped_non_elf_dll={native_skipped}."
    )

    if flags:
        lines.append(f"Interop flags ({len(flags)}):")
        for item in flags[:12]:
            lines.append(f"- {item}")
        if len(flags) > 12:
            lines.append(f"- ... plus {len(flags) - 12} additional flag(s)")
    else:
        lines.append("Interop flags: none")

    return lines


def _sqlite_interop_diagnostics() -> list[str]:
    lines: list[str] = []
    try:
        import pymodsim

        dll_root = Path(pymodsim.__file__).resolve().parent / "dlls"
        x64_dll = dll_root / "x64" / "SQLite.Interop.dll"
        top_dll = dll_root / "SQLite.Interop.dll"
        top_so = dll_root / "libSQLite.Interop.so"

        lines.append(f"SQLite diagnostics root: {dll_root}")
        lines.extend(_runtime_loadability_checks(dll_root))

        has_linux_so = top_so.exists()
        has_windows_dll = x64_dll.exists() or top_dll.exists()
        if has_windows_dll and not has_linux_so:
            lines.append(
                "SQLite interop verdict: WINDOWS_ONLY_NATIVE_INTEROP (likely Linux write failure cause)"
            )
        elif has_linux_so:
            lines.append("SQLite interop verdict: LINUX_NATIVE_INTEROP_PRESENT")
        else:
            lines.append("SQLite interop verdict: INTEROP_ARTIFACTS_NOT_FOUND")
    except Exception as exc:
        lines.append(f"SQLite diagnostics failed: {exc}")

    return lines


def _log_sqlite_interop_diagnostics() -> None:
    for line in _sqlite_interop_diagnostics():
        _log(line)


def _sqlite_interop_hint() -> str:
    try:
        import pymodsim

        dll_root = Path(pymodsim.__file__).resolve().parent / "dlls"
        x64_dll = dll_root / "x64" / "SQLite.Interop.dll"
        top_dll = dll_root / "SQLite.Interop.dll"
        top_so = dll_root / "libSQLite.Interop.so"

        has_so = top_so.exists()
        pe_windows = False

        for candidate in (x64_dll, top_dll):
            if candidate.exists():
                with candidate.open("rb") as fp:
                    pe_windows = fp.read(2) == b"MZ"
                if pe_windows:
                    break

        if pe_windows and not has_so:
            return (
                "Likely root cause: SQLite native interop is Windows-only in this environment "
                "(SQLite.Interop.dll PE binary found, no Linux libSQLite.Interop.so found)."
            )
    except Exception:
        pass

    return ""


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: modsim_linux_smoke_test.py <realization.json>", file=sys.stderr)
        return 2

    run_root = Path.cwd().resolve()
    realization_path = _resolve_run_relative(run_root, sys.argv[1])
    if not realization_path.is_file():
        return _fail(f"Realization file not found: {realization_path}")

    with realization_path.open(encoding="utf-8") as fp:
        realization = json.load(fp)

    routing = realization.get("routing") or {}
    if routing.get("router") != "modsim":
        _log("Router is not modsim; skipping Linux smoke test.")
        return 0

    modsim_config_raw = routing.get("modsim_config_file_with_path")
    if not modsim_config_raw:
        return _fail("Routing router='modsim' requires 'modsim_config_file_with_path'.")

    modsim_config_path = _resolve_run_relative(run_root, modsim_config_raw)
    if not modsim_config_path.is_file():
        return _fail(f"MODSIM config not found: {modsim_config_path}")

    with modsim_config_path.open(encoding="utf-8") as fp:
        modsim_config = yaml.safe_load(fp) or {}

    model_file_raw = ((modsim_config.get("modsim") or {}).get("model_file"))
    if not model_file_raw:
        return _fail(f"Missing modsim.model_file in {modsim_config_path}")

    model_file = _resolve_run_relative(run_root, model_file_raw)
    if not model_file.is_file():
        return _fail(f"MODSIM model file not found: {model_file}")

    scratch_dir = run_root / ".modsim_linux_smoke"
    if scratch_dir.exists():
        shutil.rmtree(scratch_dir)
    scratch_dir.mkdir(parents=True)

    smoke_xy = scratch_dir / model_file.name
    smoke_db = scratch_dir / f"{smoke_xy.stem}OUTPUT.sqlite"
    shutil.copy2(model_file, smoke_xy)

    _log(f"Running Linux smoke test with model copy: {smoke_xy}")
    _log_sqlite_interop_diagnostics()

    try:
        model = PyModsimModel()
        model.load(str(smoke_xy))
        model.run()
        run_message = getattr(model, "_run_message", None)
    except Exception as exc:
        return _fail(f"PyMODSIM execution raised an exception: {exc}", scratch_dir)

    _log(f"Solver return code: {run_message}")
    if run_message != 0:
        return _fail(f"Solver returned non-zero status: {run_message}", scratch_dir)

    if not smoke_db.exists():
        return _fail(f"Expected SQLite output was not created: {smoke_db}", scratch_dir)

    db_size = smoke_db.stat().st_size
    _log(f"SQLite output size: {db_size} bytes")
    if db_size <= 0:
        hint = _sqlite_interop_hint()
        message = "SQLite output file is empty."
        if hint:
            message = f"{message} {hint}"
        return _fail(message, scratch_dir)

    try:
        connection = sqlite3.connect(str(smoke_db))
        try:
            tables = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
        finally:
            connection.close()
    except Exception as exc:
        return _fail(f"SQLite output could not be queried: {exc}", scratch_dir)

    if not tables:
        return _fail("SQLite output contains no tables.", scratch_dir)

    _log(f"SQLite tables found: {', '.join(name for (name,) in tables[:5])}")
    shutil.rmtree(scratch_dir)
    _log("Linux smoke test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())