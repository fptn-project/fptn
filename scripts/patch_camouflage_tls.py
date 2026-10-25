#!/usr/bin/env python3
"""Insert #include <algorithm> into camouflage-tls builder.cpp if missing.

Camouflage-tls uses std::copy_n but doesn't include <algorithm>.
On newer compilers with -Werror this fails the build.

Usage:
    python scripts/patch_camouflage_tls.py
    python scripts/patch_camouflage_tls.py /custom/path/to/builder.cpp
"""
import os
import sys


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
        # Default: look in build/_deps/ relative to current working directory
        path = "build/_deps/camouflagetls-src/src/builder.cpp"
    sys.exit(patch(path))