# SQLite / Mono P/Invoke Fix Notes

## The Problem

MODSIM's C# code uses `[DllImport("SQLite.Interop.dll")]` to call native SQLite functions (e.g. `sqlite3_step`). On Linux this file doesn't exist — the equivalent is `libSQLite.Interop.so`. When Mono can't find the library, the function pointer is NULL and the process crashes with SIGSEGV.

## Fix 1 (Implemented) — Global Mono config in Dockerfile - THIS DOES NOT WORK. 

Added to `Dockerfile` immediately after `mono-complete` is installed:

```dockerfile
RUN sed -i 's|</configuration>|  <dllmap dll="SQLite.Interop.dll" target="libsqlite3.so.0" os="!windows"/>\n</configuration>|' /etc/mono/config
```

This inserts into `/etc/mono/config`:
```xml
<dllmap dll="SQLite.Interop.dll" target="libsqlite3.so.0" os="!windows"/>
```

**Why it works:** `/etc/mono/config` is read for every assembly loaded by any Mono process, regardless of where the assembly came from. Mapping to the system `libsqlite3.so.0` avoids any `LD_LIBRARY_PATH` dependency.

**Downside:** Lives in the container, not in py-modsim itself. Any environment running py-modsim without this container needs a separate fix.

---

## Fix 2 (Not yet tried) — Add `.dll` extension in py-modsim's `pyms.py`

In `py-modsim/src/pymodsim/pyms.py`, change:
```python
clr.AddReference(str(_DLLS / "System.Data.SQLite"))
```
to:
```python
clr.AddReference(str(_DLLS / "System.Data.SQLite.dll"))
```

**Why it might work:** Without an extension, pythonnet/Mono treats the argument as an assembly *name* and searches the GAC (system registry). When Mono loads from the GAC it doesn't know the py-modsim dlls directory, so it never reads `System.Data.SQLite.dll.config` sitting next to the DLL. Passing a full path ending in `.dll` forces Mono to load from that exact file and track its directory — making the per-assembly config findable.

**Upside:** Tiny change. No system config touched.  
**Risk:** May not be sufficient if Mono still doesn't honor the per-assembly config for other reasons.

---

## Fix 3 (Not yet tried) — `MONO_CONFIG` env var in py-modsim

The most self-contained upstream fix. py-modsim ships its own Mono config file and sets `MONO_CONFIG` before the runtime initializes.

### Step 1 — Add `dlls/mono-config.xml` to py-modsim

```xml
<configuration>
  <dllmap dll="SQLite.Interop.dll" target="libSQLite.Interop.so" os="linux"/>
</configuration>
```

### Step 2 — Set env var before `import clr` in `pyms.py`

```python
from pathlib import Path
import os

_DLLS = Path(__file__).parent / "dlls"
os.environ.setdefault("MONO_CONFIG", str(_DLLS / "mono-config.xml"))

import clr  # Mono runtime initializes here and reads MONO_CONFIG
```

**Why it works:** `MONO_CONFIG` replaces `/etc/mono/config` entirely. Setting it before `import clr` means Mono reads py-modsim's config at runtime startup, with the correct mapping, before any assembly is loaded.

**Upside:** Fully self-contained in py-modsim. Works on any Linux machine without container or system changes.  
**Risk:** If something else imports `clr` before `pyms.py` runs, the env var needs to be set even earlier (e.g. in `__init__.py`).
