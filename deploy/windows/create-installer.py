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
DEPENDS_APP_SPLIT_DRIVER_PATH = DEPENDS_DIR / "mullvad-split-tunnel.sys"
DEPENDS_APP_SPLIT_LICENSE_PATH = DEPENDS_DIR / "LICENSE-MPL-2.0.txt"
DEPENDS_APP_SPLIT_NOTICE_PATH = DEPENDS_DIR / "APP_SPLIT_THIRD_PARTY_NOTICE.txt"

DEFAULT_APP_SPLIT_DRIVER_URL = (
    "https://raw.githubusercontent.com/mullvad/mullvadvpn-app-binaries/"
    "main/x86_64-pc-windows-msvc/split-tunnel/mullvad-split-tunnel.sys"
)
APP_SPLIT_LICENSE_URL = (
    "https://raw.githubusercontent.com/mullvad/win-split-tunnel/"
    "master/LICENSE-MPL.txt"
)

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
    # Respect Conan 2's documented CONAN_HOME override first. This also avoids
    # issues with tools that cannot handle non-ASCII Windows user profiles.
    conan_home = os.environ.get("CONAN_HOME")
    if conan_home:
        path = pathlib.Path(conan_home)
        if path.exists() and path.is_dir():
            return path

    home_path = pathlib.Path.home()
    conan_paths = [home_path / ".conan2", home_path / ".conan"]
    for path in conan_paths:
        if path.exists() and path.is_dir():
            return path
    raise FileNotFoundError("Conan path could not be detected.")


def copy_qt_libraries(frameworks_path: pathlib.Path):
    conan_path = get_conan_path()
    print(f"Detected Conan path: {conan_path}")

    qt_libs = run_command(f'dir /S /B "{conan_path}"\\*.dll')
    qt_lib_paths = qt_libs.splitlines()
    frameworks_qt_plugins_path = frameworks_path / "plugins"
    for lib in qt_lib_paths:
        lib_path = pathlib.Path(lib)
        lib_name = lib_path.name
    for lib in qt_lib_paths:
        lib_path = pathlib.Path(lib)
        lib_name = lib_path.name
        if r"qtbase/bin/" in str(lib_path.as_posix()):
            if r".6.7.3.dll" in lib_name:
                lib_name = lib_name.replace(".6.7.3.dll", ".6.dll")
            print(f"Copy {lib} -> {frameworks_path / lib_name}")
            shutil.copy(lib, frameworks_path / lib_name)
        elif "qtbase/plugins" in str(lib_path.as_posix()):
            separated = str(lib_path.as_posix()).split("qtbase/plugins/")
            plugin_folder = frameworks_qt_plugins_path / separated[1].replace(lib_name, "")
            os.makedirs(plugin_folder, exist_ok=True)
            print(f"Copy {lib_path} -> {plugin_folder / lib_name}")
            shutil.copy(lib, plugin_folder / lib_name)


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

    # Download the optional signed application split-tunnel driver and its
    # MPL-2.0 license. The runtime feature is disabled by default and will
    # gracefully fall back to normal VPN routing if the driver cannot start.
    app_split_driver_url = os.environ.get(
        "FPTN_APP_SPLIT_DRIVER_URL", DEFAULT_APP_SPLIT_DRIVER_URL
    )
    try:
        download_file(app_split_driver_url, DEPENDS_APP_SPLIT_DRIVER_PATH)
        download_file(APP_SPLIT_LICENSE_URL, DEPENDS_APP_SPLIT_LICENSE_PATH)
        with open(DEPENDS_APP_SPLIT_DRIVER_PATH, "rb") as driver_file:
            if driver_file.read(2) != b"MZ":
                raise ValueError("Downloaded application split-tunnel driver is not a PE file")
    except Exception as err:
        # App split tunneling is optional. Do not break the whole Windows
        # installer when GitHub is unavailable; runtime will fall back to the
        # ordinary VPN and log that the driver is missing. Remove partial
        # artifacts so we never redistribute the driver without its license.
        print(f"Warning: application split-tunnel driver was not prepared: {err}")
        for optional_file in (
            DEPENDS_APP_SPLIT_DRIVER_PATH,
            DEPENDS_APP_SPLIT_LICENSE_PATH,
        ):
            try:
                optional_file.unlink(missing_ok=True)
            except Exception:
                pass
    app_split_notice = INSTALLER_DIR / "resources" / "APP_SPLIT_THIRD_PARTY_NOTICE.txt"
    shutil.copy(app_split_notice, DEPENDS_APP_SPLIT_NOTICE_PATH)

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
