import os
import subprocess
import shutil

from pathlib import Path

from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMake, cmake_layout
from conan.tools.files import copy
from conan.tools.scm import Git


class FptnProxy(ConanFile):
    name = "fptn-lib"
    version = "0.0.0"
    settings = (
        "os",
        "arch",
        "compiler",
        "build_type",
    )
    requires = (
        "argparse/3.2",
        "cpp-httplib/0.46.1",
        "fmt/12.1.0",
        "nlohmann_json/3.12.0",
    )
    generators = ("CMakeDeps",)
    default_options = {
        "*:fPIC": True,
        "*:shared": False,
        "fptn/*:build_only_fptn_lib": True,
        "fptn/*:with_gui_client": False,
    }

    def requirements(self):
        self._register_local_recipe("fptn", "fptn", "0.0.0")

    def layout(self):
        cmake_layout(self)

    def generate(self):
        tc = CMakeToolchain(self)
        if "fptn" in self.dependencies:
            fptn_dep = self.dependencies["fptn"]
            tc.variables["FPTN_INCLUDE_DIR"] = fptn_dep.cpp_info.includedirs[0] if fptn_dep.cpp_info.includedirs else ""
            tc.variables["FPTN_LIBRARIES"] = fptn_dep.cpp_info.libs[0] if fptn_dep.cpp_info.libs else "fptn"
            if fptn_dep.cpp_info.libdirs:
                tc.variables["FPTN_LIBRARY_DIR"] = fptn_dep.cpp_info.libdirs[0]
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def config_options(self):
        pass

    def _clone_fptn(self):
        fptn_path = Path(__file__).parent / "libs" / "fptn"
        if fptn_path.exists():
            shutil.rmtree(fptn_path)

        self.output.info("Cloning fptn repository...")
        git = Git(self)
        git.clone(url="https://github.com/batchar2/fptn.git", target=fptn_path.as_posix())

    def _register_local_recipe(self, recipe, name, version, override=False, force=False):
        self._clone_fptn()
        script_dir = os.path.dirname(os.path.abspath(__file__))
        recipe_rel_path = os.path.join(script_dir, "libs", "fptn")

        if os.path.exists(recipe_rel_path):
            self.output.info(f"Exporting local recipe: {recipe_rel_path}")
            subprocess.run(
                [
                    "conan",
                    "export",
                    recipe_rel_path,
                    f"--name={name}",
                    f"--version={version}",
                    "--user=local",
                    "--channel=local",
                ],
                check=True,
                cwd=script_dir,
            )
            self.requires(f"{name}/{version}@local/local", override=override, force=force)
        else:
            self.output.warning(f"Recipe path not found: {recipe_rel_path}")
