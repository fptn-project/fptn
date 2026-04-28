import os

from conan import ConanFile
from conan.tools.files import get, replace_in_file
from conan.tools.cmake import CMake, CMakeToolchain, cmake_layout


class BoringSSLConan(ConanFile):
    name = "openssl"
    version = "boringssl"

    settings = "os", "arch", "compiler", "build_type"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options = {"shared": False, "fPIC": True}

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def layout(self):
        cmake_layout(self)

    def source(self):
        url = "https://github.com/batchar2/boringssl/archive/refs/heads/working-russia-tls-handshake.tar.gz"
        get(self, url, strip_root=True)

    def generate(self):
        tc = CMakeToolchain(self)
        tc.variables["BUILD_TESTING"] = False
        tc.variables["ENABLE_EXPRESSION_TESTS"] = False

        # Apple mobile platforms need explicit SDK settings when cross-building.
        if self.settings.os in ["iOS", "tvOS"]:
            tc.variables["CMAKE_SYSTEM_NAME"] = str(self.settings.os)
            tc.variables["CMAKE_OSX_DEPLOYMENT_TARGET"] = str(self.settings.os.version)
            tc.variables["CMAKE_OSX_ARCHITECTURES"] = self.settings.arch
            tc.variables["CMAKE_MACOSX_BUNDLE"] = False
            sdk = str(self.settings.os.sdk).lower()
            if self.settings.os == "tvOS":
                tc.variables["CMAKE_OSX_SYSROOT"] = (
                    "appletvsimulator" if "simulator" in sdk else "appletvos"
                )
            else:
                tc.variables["CMAKE_OSX_SYSROOT"] = (
                    "iphonesimulator" if "simulator" in sdk else "iphoneos"
                )
            tc.variables["CMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED"] = "NO"
            tc.variables["CMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED"] = "NO"
            tc.variables["CMAKE_XCODE_ATTRIBUTE_ENABLE_BITCODE"] = "YES"
            tc.variables["CMAKE_XCODE_ATTRIBUTE_ONLY_ACTIVE_ARCH"] = "NO"

        tc.generate()

    def build(self):
        replace_in_file(
            self,
            os.path.join(self.source_folder, "CMakeLists.txt"),
            "  install(TARGETS bssl)\n",
            "",
        )
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.components["ssl"].libs = ["ssl"]
        self.cpp_info.components["crypto"].libs = ["crypto"]

        # include dir
        self.cpp_info.includedirs = ["include"]
        self.cpp_info.components["ssl"].includedirs = ["include"]
        self.cpp_info.components["crypto"].includedirs = ["include"]

        # for CMake find_package(OpenSSL)
        self.cpp_info.set_property("cmake_file_name", "OpenSSL")
        self.cpp_info.components["ssl"].set_property("cmake_target_name", "OpenSSL::SSL")
        self.cpp_info.components["crypto"].set_property("cmake_target_name", "OpenSSL::Crypto")

        if self.settings.os in ["iOS", "tvOS"]:
            self.cpp_info.frameworks = ["Security", "Foundation", "CoreFoundation"]
            self.cpp_info.system_libs = ["c++"]
