#!/usr/bin/env bash

set -e

echo "Starting build in AlmaLinux 9 container..."

podman run --rm \
  -v "$(pwd):/work:z" \
  -v "$(pwd)/.conan2_cache:/root/.conan2:z" \
  almalinux:9 bash -c "
set -e
dnf install -y python3-pip cmake gcc-c++ make git rpm-build
pip3 install conan==2.24.0
conan profile detect --force
cd /work
conan install . --output-folder=build_alma --build=missing -s compiler.cppstd=17 -o with_gui_client=False -c tools.system.package_manager:mode=install --settings build_type=Release
cd build_alma
cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
cmake --build . --config Release --target build-rpm
cp fptn-server-*.rpm /work/
echo 'Build finished! RPM copied to /work/'
"
