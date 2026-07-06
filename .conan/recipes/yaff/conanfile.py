import os

from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, cmake_layout
from conan.tools.files import get, replace_in_file


class YaffConan(ConanFile):
    name = "yaff"
    version = "0.0.0"

    settings = "os", "arch", "compiler", "build_type"
    generators = ("CMakeDeps",)

    requires = ("protobuf/5.29.3",)

    default_options = {
        "protobuf/*:lite": True,
        "protobuf/*:upb": False,
        "protobuf/*:with_rtti": False,
        "protobuf/*:with_zlib": False,
        "protobuf/*:debug_suffix": False,
    }

    def layout(self):
        cmake_layout(self)

    def build_requirements(self):
        self.tool_requires("protobuf/5.29.3")

    def source(self):
        get(
            self,
            "https://github.com/yandex/yaff/archive/refs/heads/main.zip",
            strip_root=True,
        )
        replace_in_file(
            self,
            os.path.join(self.source_folder, "src", "protoc-plugin", "CMakeLists.txt"),
            "install(TARGETS yaff_protoc_plugin\n    EXPORT YaFFTargets\n",
            "install(TARGETS yaff_protoc_plugin\n",
        )
        # MSVC only forward-declares std::ostream via <string_view>, so the
        # operator<< in array.h fails with an incomplete type. Pull in <ostream>.
        replace_in_file(
            self,
            os.path.join(self.source_folder, "include", "yaff", "array.h"),
            "#include <string_view>",
            "#include <ostream>\n#include <string_view>",
        )

    def generate(self):
        tc = CMakeToolchain(self)
        tc.variables["YAFF_BUILD_TESTS"] = False
        tc.variables["YAFF_BUILD_BENCHMARKS"] = False
        tc.variables["YAFF_BUILD_EXAMPLES"] = False
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.set_property("cmake_find_mode", "none")
        self.cpp_info.builddirs = ["lib/cmake/YaFF"]
        self.cpp_info.bindirs = ["bin"]
