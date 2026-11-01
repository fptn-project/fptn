import os
import re
import sys
import shutil
import pathlib
import platform
import datetime
import argparse
import subprocess

import requests

INNOSETUP_DEFAULT_PATH = r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe"

REPOSITORY_FOLDER = pathlib.Path(__file__).parent.parent.parent

INSTALLER_DIR = pathlib.Path(__file__).parent.resolve() / "installer"

TMP_DIR = INSTALLER_DIR / "tmp"
TMP_DIR.mkdir(parents=True, exist_ok=True)

DEPENDS_DIR = INSTALLER_DIR / "depends"
DEPENDS_DIR.mkdir(parents=True, exist_ok=True)

DEPENDS_QT_DIR = DEPENDS_DIR / "qt"
DEPENDS_QT_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_DIR = INSTALLER_DIR / "Output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

DEPENDS_WINTUN_DLL_PATH = DEPENDS_DIR / "wintun.dll"
DEPENDS_VC_REDIST_PATH = DEPENDS_DIR / "vc_redist.exe"

APP_FPTN_CLIENT = DEPENDS_DIR / "fptn-client.exe"
APP_FPTN_CLIENT_CLI = DEPENDS_DIR / "fptn-client-cli.exe"


def is_windows_x86_64() -> bool:
    if platform.system() != "Windows":
        raise EnvironmentError("This function is only for Windows systems.")
    architecture = platform.machine().lower()
    return architecture in ("x86_64", "amd64")


def is_arm_64() -> bool:
    architecture = platform.machine().lower()
    return architecture in ("aarch64", "arm64")


def download_file(url: str, destination_path: pathlib.Path) -> bool:
    try:
        response = requests.get(url, allow_redirects=True, timeout=120)
        if response.status_code == 200:
            with open(destination_path, "wb") as file:
                file.write(response.content)
            print(f"File downloaded successfully: {destination_path}")
            return True
        raise ConnectionError(f"Failed to download file: HTTP {response.status_code} {response.reason}")
    except Exception as err:
        raise err


def replace_values_in_innosetupfile(file_path: pathlib.Path, replacements: dict):
    with open(file_path, "r", encoding="utf-8") as file:
        content = file.read()

    for key, value in replacements.items():
        pattern = rf'#define {key} ".*?"'
        replacement = rf'#define {key} "{value}"'
        content = re.sub(pattern, replacement, content)
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(content)


def run_command(command: str) -> str:
    """Run a shell command and return its output."""
    try:
        print("COMMAND>", command)
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        result.check_returncode()
        print(result.stderr)
        return result.stdout
    except Exception as err:
        print("Output:", err.stdout)
        print("Errors:", err.stderr)
        raise err


def get_conan_path() -> pathlib.Path:
    home_path = pathlib.Path.home()
    conan_paths = [home_path / ".conan2", home_path / ".conan"]
    for path in conan_paths:
        if path.exists() and path.is_dir():
            return path
    raise FileNotFoundError("Conan path could not be detected in the home directory.")


def copy_qt_libraries(frameworks_path: pathlib.Path):
    conan_path = get_conan_path()
    print(f"Detected Conan path: {conan_path}")

    # Find Qt6Core.dll to determine the Qt version and bin directory.
    # On Windows, Qt DLLs are typically in qtbase/bin/.
    # On Linux/macOS, they are in qtbase/lib/.
    qt_core_dlls = run_command(
        f'dir /S /B "{conan_path}"\\Qt6Core*.dll'
    ).splitlines()

    qt_version = None
    qt_bin_dir = None
    qt_core_dlls_mtime = 0  # Track the modification time of the newest DLL
    for dll_path_str in qt_core_dlls:
        dll_path = pathlib.Path(dll_path_str)
        # Look for files like Qt6Core.6.7.3.dll or Qt6Core.6.11.1.dll
        name = dll_path.name
        # Normalize the path to search for "qtbase/bin" OR "qtbase/lib"
        posix_path = str(dll_path.as_posix())
        is_qt_path = (
            r"qtbase/bin/" in posix_path or
            r"qtbase/lib/" in posix_path
        )
        if is_qt_path and name.startswith("Qt6Core."):
            # Extract the version from the filename: Qt6Core.6.7.3.dll -> 6.7.3
            version_part = name.replace("Qt6Core.", "").replace(".dll", "")
            # Pick the most recent one (by file modification time)
            try:
                mtime = dll_path.stat().st_mtime
            except OSError:
                continue
            if qt_version is None or mtime > qt_core_dlls_mtime:
                qt_version = version_part
                qt_bin_dir = dll_path.parent
                qt_core_dlls_mtime = mtime

    if not qt_version or not qt_bin_dir:
        raise FileNotFoundError(
            "Could not find Qt6Core.dll in Conan cache. "
            "Make sure Qt is built with -o with_gui_client=True"
        )

    print(f"Detected Qt version: {qt_version}")
    print(f"Qt bin directory: {qt_bin_dir}")

    # Copy all Qt6*.dll from the found directory, renaming the version
    # Qt6Core.6.7.3.dll -> Qt6Core.dll
    for dll in qt_bin_dir.glob("Qt6*.dll"):
        # Skip debug files ('d.dll')
        if dll.name.endswith("d.dll"):
            continue
        target_name = dll.name
        # Strip the version from the name: Qt6Core.6.7.3.dll -> Qt6Core.dll
        # Split by dots: ['Qt6Core', '6', '7', '3', 'dll']
        parts = target_name.split(".")
        if len(parts) >= 3 and parts[1].isdigit():
            # Remove all numeric version segments
            target_name = parts[0] + ".dll"
        print(f"Copy {dll} -> {frameworks_path / target_name}")
        shutil.copy(dll, frameworks_path / target_name)

    # Copy plugins
    frameworks_qt_plugins_path = frameworks_path / "plugins"
    # Look for the plugins folder relative to qt_bin_dir
    # qt_bin_dir = .../qtbase/bin, plugins = .../qtbase/plugins
    qt_plugins_dir = qt_bin_dir.parent / "plugins"
    if not qt_plugins_dir.exists():
        # In case the Conan cache path is: .../p/bin, plugins = .../p/plugins
        qt_plugins_dir = qt_bin_dir.parent.parent / "plugins"

    if qt_plugins_dir.exists():
        print(f"Qt plugins directory: {qt_plugins_dir}")
        for plugin_file in qt_plugins_dir.rglob("*.dll"):
            rel_path = plugin_file.relative_to(qt_plugins_dir)
            target = frameworks_qt_plugins_path / rel_path
            target.parent.mkdir(parents=True, exist_ok=True)
            print(f"Copy {plugin_file} -> {target}")
            shutil.copy(plugin_file, target)
    else:
        print(f"WARNING: Qt plugins directory not found near {qt_bin_dir}")


def compile_inno_setup_script(script_path: pathlib.Path, output_dir: pathlib.Path) -> bool:
    command = [INNOSETUP_DEFAULT_PATH, script_path]
    # if output_dir:
    #     command.append(f"/O{output_dir}")
    try:
        result = subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        print("Inno Setup compiled successfully.")

        output = result.stdout
        if len(output) > 0:
            print(output)

        warnings = result.stderr
        if len(warnings) > 0:
            print("Warnings:", result.stderr)
        return True
    except Exception as err:
        print("Failed to compile Inno Setup script: ", err)
        print("Output:", err.stdout)
        print("Errors:", err.stderr)
        raise err


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A script to manage the build process for FPTN Client.")
    parser.add_argument(
        "--wintun-dll",
        type=pathlib.Path,
        required=True,
        help="The path to the wintun dll",
    )
    parser.add_argument(
        "--fptn-client",
        type=pathlib.Path,
        required=True,
        help="The path to the FPTN client executable.",
    )
    parser.add_argument(
        "--fptn-client-cli",
        type=pathlib.Path,
        required=True,
        help="The path to the FPTN client CLI executable.",
    )
    parser.add_argument("--version", required=True, help="Version")
    parser.add_argument("--output-folder", required=True, help="output-folder")

    args = parser.parse_args()

    if is_arm_64():
        download_file("https://aka.ms/vs/17/release/vc_redist.arm64.exe", DEPENDS_VC_REDIST_PATH)
    elif is_windows_x86_64():
        download_file("https://aka.ms/vs/17/release/vc_redist.x64.exe", DEPENDS_VC_REDIST_PATH)
    else:
        raise EnvironmentError("Unsuported system!")

    # copy wintun dll
    shutil.copy(args.wintun_dll, DEPENDS_WINTUN_DLL_PATH)
    # copy clients
    shutil.copy(args.fptn_client, APP_FPTN_CLIENT)
    shutil.copy(args.fptn_client_cli, APP_FPTN_CLIENT_CLI)

    # copy SNI files from deploy/sni to depends/sni
    sni_source = REPOSITORY_FOLDER / "deploy" / "sni"
    sni_dest = DEPENDS_DIR / "sni"
    if sni_source.exists():
        print(f"Copying SNI files from {sni_source} to {sni_dest}")
        shutil.copytree(sni_source, sni_dest, dirs_exist_ok=True)
    else:
        print(f"Warning: SNI source folder not found: {sni_source}")

    # prepare innosetup
    INNOSETUP_SCRIPT_PATH = INSTALLER_DIR / "fptn-installer.iss"
    PREPARED_INNOSETUP_SCRIPT_PATH = INSTALLER_DIR / "tmp.iss"
    shutil.copy(INNOSETUP_SCRIPT_PATH, PREPARED_INNOSETUP_SCRIPT_PATH)
    arch = is_arm_64()
    replace_values_in_innosetupfile(
        PREPARED_INNOSETUP_SCRIPT_PATH,
        {
            "APP_VERSION_NAME": args.version,
            "APP_VERSION_NUMBER": datetime.datetime.now().strftime("%Y.%m.%d.%H%M"),
            "APP_COPYRIGHT_YEAR": str(datetime.datetime.now().year),
        },
    )

    # prepare qt
    conan_path = get_conan_path()
    copy_qt_libraries(DEPENDS_QT_DIR)

    # change dir
    os.chdir(INSTALLER_DIR.resolve().as_posix())

    # change resources
    TOOLS_RC_EDIT = TMP_DIR / "rcedit.exe"
    download_file(
        "https://github.com/electron/rcedit/releases/download/v2.0.0/rcedit-x64.exe",
        TOOLS_RC_EDIT,
    )
    ICON_FILE = INSTALLER_DIR / "resources" / "icons" / "app.ico"
    run_command(
        f'"{TOOLS_RC_EDIT.as_posix()}" "{APP_FPTN_CLIENT.as_posix()}" --set-product-version "{args.version}" --set-icon "{ICON_FILE.as_posix()}"'
    )

    # change permissions
    manifest = INSTALLER_DIR / "app.manifest"
    run_command(f'mt.exe -manifest "{manifest.as_posix()}" -outputresource:"{APP_FPTN_CLIENT.as_posix()}";1')
    run_command(f'mt.exe -manifest "{manifest.as_posix()}" -outputresource:"{APP_FPTN_CLIENT_CLI.as_posix()}";1')

    compile_inno_setup_script(PREPARED_INNOSETUP_SCRIPT_PATH, OUTPUT_DIR)
    arch = "arm64" if is_arm_64() else "x64_x86"
    output_file = pathlib.Path(args.output_folder) / f"FptnClientInstaller-{args.version}-windows-{arch}.exe"
    shutil.copy(INSTALLER_DIR / "Output" / "FptnClientInstaller.exe", output_file)
