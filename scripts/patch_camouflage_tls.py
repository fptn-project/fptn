#!/usr/bin/env python3
"""Insert #include <algorithm> into camouflage-tls builder.cpp if missing.

Camouflage-tls uses std::copy_n but doesn't include <algorithm>.
On newer compilers with -Werror this fails the build.

This script is fully autonomous:
  - If a path is provided as argument, it uses that path.
  - Otherwise, it auto-discovers the file by searching for the
    camouflage-tls source folder inside the build tree.

Usage:
    python scripts/patch_camouflage_tls.py
    python scripts/patch_camouflage_tls.py /custom/path/to/builder.cpp
"""
import os
import sys
import glob


def find_builder_cpp() -> str:
    """Auto-discover builder.cpp inside the build tree."""
    # Search common Conan 2 / CMake FetchContent patterns
    patterns = [
        "build/_deps/camouflagetls-src/src/builder.cpp",
        "build/_deps/camouflage-tls-src/src/builder.cpp",
        "build/_deps/camouflagetls-src/src/builder.cxx",
        # Glob patterns to catch any hash-prefixed Conan folder
        "build/_deps/camouflagetls-src/**/builder.cpp",
        "build/_deps/**/camouflagetls-src/**/builder.cpp",
        "build/_deps/**/camouflage-tls-src/**/builder.cpp",
        # Fallback: search anywhere under build/
        "build/**/camouflagetls/**/builder.cpp",
        "build/**/camouflage-tls/**/builder.cpp",
    ]
    for pattern in patterns:
        for found in glob.glob(pattern, recursive=True):
            if os.path.isfile(found):
                return found
    return ""


def patch(path: str) -> int:
    if not os.path.exists(path):
        print(f"WARNING: {path} not found — camouflage-tls not fetched yet")
        return 0
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    if "#include <algorithm>" in content:
        print(f"Already patched: {path}")
        return 0
    lines = content.split("\n")
    for i, line in enumerate(lines):
        if line.startswith("#include"):
            lines.insert(i, "#include <algorithm>")
            break
    else:
        lines.insert(0, "#include <algorithm>")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Patched: {path}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        path = find_builder_cpp()
        if not path:
            # Fallback to the default expected path (for warning message)
            path = "build/_deps/camouflagetls-src/src/builder.cpp"
    sys.exit(patch(path))