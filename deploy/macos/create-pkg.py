#!/usr/bin/env python3

import os
import sys
import shutil
import pathlib
import argparse
import platform
import plistlib
import tempfile
import subprocess

from macos_pkg_builder import Packages


APP_NAME = "FptnClient"
SCRIPT_FOLDER = pathlib.Path(__file__).parent
REPOSITORY_FOLDER = pathlib.Path(__file__).parent.parent.parent
ICON = SCRIPT_FOLDER / "assets" / "FptnClient.icns"


def run_command(command, cwd=None):
    result = subprocess.run(
        command,
        shell=True,
        cwd=cwd,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Command '{command}' failed with error: {result.stderr.strip()}")
    return result.stdout.strip()



def create_app(
    app_path: pathlib.Path,
    fptn_client_cli: pathlib.Path,
    fptn_client_gui: pathlib.Path,
    version: str,
) -> bool:
    print(app_path)
    try:
        app_contents_path = app_path / "Contents"
        macos_path = app_contents_path / "MacOS"
        resources_path = app_contents_path / "Resources"
        frameworks_path = app_contents_path / "Frameworks"
        frameworks_qt_plugins_path = app_contents_path / "Frameworks" / "plugins"
        os.makedirs(macos_path, exist_ok=True)
        os.makedirs(resources_path, exist_ok=True)
        os.makedirs(frameworks_path, exist_ok=True)
        os.makedirs(frameworks_qt_plugins_path, exist_ok=True)

        # Сopy SNI files from deploy/sni to Resources/SNI
        sni_source = REPOSITORY_FOLDER / "deploy" / "sni"
        sni_dest = resources_path / "SNI"
        if sni_source.exists():
            print(f"Copying SNI files from {sni_source} to {sni_dest}")
            shutil.copytree(sni_source, sni_dest, dirs_exist_ok=True)
        else:
            print(f"Warning: SNI source folder not found: {sni_source}")

        # copy cli program
        binary_dest = macos_path / "fptn-client-cli"
        shutil.copy(fptn_client_cli, binary_dest)
        os.chmod(binary_dest, 0o755)
        # copy wrapper of program
        fptn_client_cli_wrapper_sh = SCRIPT_FOLDER / "scripts" / "fptn-client-cli-wrapper.sh"
        fptn_client_cli_wrapper_sh_dest = macos_path / "fptn-client-cli-wrapper.sh"
        shutil.copy(fptn_client_cli_wrapper_sh, fptn_client_cli_wrapper_sh_dest)
        os.chmod(binary_dest, 0o755)

        # --- copy gui program ---
        binary_dest = macos_path / "fptn-client-gui"
        shutil.copy(fptn_client_gui, binary_dest)
        # Fix rpath
        run_command(f'install_name_tool -add_rpath @executable_path/../Frameworks {macos_path / "fptn-client-gui"}')

        os.chmod(binary_dest, 0o755)
        fptn_client_gui_wrapper_sh = SCRIPT_FOLDER / "scripts" / "fptn-client-gui-wrapper.sh"
        fptn_client_gui_wrapper_sh_dest = macos_path / "fptn-client-gui-wrapper.sh"
        shutil.copy(fptn_client_gui_wrapper_sh, fptn_client_gui_wrapper_sh_dest)
        os.chmod(binary_dest, 0o4755)  # 0o755)

        # Find the newest Qt version by looking for libQt6Core.dylib
        qt_core_dylibs = run_command(
            r'find ~/.conan2 -type f -name "libQt6Core.*.dylib" | grep "qtbase/lib"'
        ).splitlines()

        qt_version = None
        qt_lib_dir = None
        qt_core_mtime = 0
        for dylib_path_str in qt_core_dylibs:
            dylib_path = pathlib.Path(dylib_path_str)
            name = dylib_path.name
            # Extract the version from the filename: libQt6Core.6.7.3.dylib -> 6.7.3
            if name.startswith("libQt6Core.") and name.endswith(".dylib"):
                version_part = name.replace("libQt6Core.", "").replace(".dylib", "")
                # Pick the most recent one (by file modification time)
                mtime = dylib_path.stat().st_mtime
                if qt_version is None or mtime > qt_core_mtime:
                    qt_version = version_part
                    qt_lib_dir = dylib_path.parent
                    qt_core_mtime = mtime

        if not qt_version or not qt_lib_dir:
            raise FileNotFoundError(
                "Could not find libQt6Core.dylib in Conan cache. "
                "Make sure Qt is built with -o with_gui_client=True"
            )

        print(f"Detected Qt version: {qt_version}")
        print(f"Qt lib directory: {qt_lib_dir}")

        # Copy all Qt6*.dylib from the found directory, renaming the version
        # libQt6Core.6.7.3.dylib -> libQt6Core.6.dylib
        for dylib in qt_lib_dir.glob("libQt6*.dylib"):
            target_name = dylib.name
            # Strip the version from the name: libQt6Core.6.7.3.dylib -> libQt6Core.6.dylib
            # Split by dots: ['libQt6Core', '6', '7', '3', 'dylib']
            parts = target_name.split(".")
            if len(parts) >= 4 and parts[1].isdigit():
                # Keep only the major version number: libQt6Core.6.dylib
                target_name = f"{parts[0]}.{parts[1]}.dylib"
            print(f"Copy {dylib} -> {frameworks_path / target_name}")
            shutil.copy(dylib, frameworks_path / target_name)

        # Copy Qt plugins
        qt_plugins_dir = qt_lib_dir.parent / "plugins"
        if qt_plugins_dir.exists():
            print(f"Qt plugins directory: {qt_plugins_dir}")
            for plugin_file in qt_plugins_dir.rglob("*.dylib"):
                rel_path = plugin_file.relative_to(qt_plugins_dir)
                target = frameworks_qt_plugins_path / rel_path
                target.parent.mkdir(parents=True, exist_ok=True)
                print(f"Copy {plugin_file} -> {target}")
                shutil.copy(plugin_file, target)
        else:
            print(f"WARNING: Qt plugins directory not found near {qt_lib_dir}")

        # copy icon
        icon_dest = resources_path / ICON.name
        shutil.copy(ICON, icon_dest)
        # Create Info.plist
        plist = {
            "CFBundleName": APP_NAME,
            "CFBundleExecutable": "fptn-client-gui-wrapper.sh",
            "CFBundleIdentifier": "com.fptn.vpn",
            "CFBundlePackageType": "APPL",
            "CFBundleVersion": version,
            "CFBundleIconFile": ICON.name,
            "LSUIElement": True,
            "LSApplicationCategoryType": "public.app-category.utilities",
            "LSRequiresNativeExecution": True,
            "NSHighResolutionCapable": True,
            "LD_LIBRARY_PATH": "@executable_path/../Frameworks",
            "RunAtLoad": True,
            "KeepAlive": True,
            "UserName": "root",
            "NSAllowsArbitraryLoads": True,
            "NSClipboardUsageDescription": "Requires clipboard access to copy and paste data.",
        }

        with open(app_contents_path / "Info.plist", "wb") as plist_file:
            plistlib.dump(plist, plist_file)

    except Exception as e:
        print(f"Error creating .app: {e}")
        raise e
    return True


def create_pkg(app_path: pathlib.Path, version: str) -> bool:
    try:
        post_install = SCRIPT_FOLDER / "scripts" / "post_install.sh"
        machine = "apple-silicon" if platform.machine() == "arm64" else "intel"
        pkg_obj = Packages(
            pkg_output=f"fptn-client-{version}-{machine}.pkg",
            pkg_bundle_id="com.fptn-vpn.installer",
            pkg_as_distribution=True,
            pkg_title="FPTN-VPN",
            pkg_postinstall_script=str(post_install.resolve()),
            pkg_file_structure={
                str(app_path.resolve()): f"/Applications/{APP_NAME}.app",
            },
        )
        if pkg_obj.build():
            return True
        else:
            print("Error building package.")
    except Exception as e:
        print(f"Error creating package: {e}")
        raise e
    return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PKG build configuration.")
    parser.add_argument("--fptn-client-cli", required=True, help="Path to the cli application binary.")
    parser.add_argument("--fptn-client-gui", required=True, help="Path to the gui application binary.")
    parser.add_argument("--version", required=True, help="Version")
    args = parser.parse_args()

    fptn_client_cli = pathlib.Path(args.fptn_client_cli)
    fptn_client_gui = pathlib.Path(args.fptn_client_gui)
    if not fptn_client_cli.is_file() or not fptn_client_gui.is_file():
        print(f"Binary file does not exist: {fptn_client_cli} or {fptn_client_gui}")
        sys.exit(1)
    with tempfile.TemporaryDirectory() as temp_dir:
        app_path = pathlib.Path(temp_dir) / f"{APP_NAME}-{args.version}.app"
        if create_app(app_path, fptn_client_cli, fptn_client_gui, args.version):
            if create_pkg(app_path, args.version):
                print(f"Package created successfully")
            else:
                print("Failed to create package.")
                sys.exit(1)
        else:
            print("Failed to create .app")
            sys.exit(1)
