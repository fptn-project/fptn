include(FetchContent)

FetchContent_Declare(YaFF URL https://github.com/yandex/yaff/archive/refs/heads/main.zip)
FetchContent_MakeAvailable(YaFF)

if(NOT EXISTS ${yaff_SOURCE_DIR}/cmake/YaFFGenerate.cmake)
  message(FATAL_ERROR "YaFF sources are incomplete: ${yaff_SOURCE_DIR}")
endif()

set(YAFF_PROTO_IMPORT_DIR ${yaff_SOURCE_DIR}/include)
include(${yaff_SOURCE_DIR}/cmake/YaFFGenerate.cmake)

# --- disable clang-tidy for YaFF third-party sources ---
foreach(dir ${yaff_SOURCE_DIR} ${yaff_BINARY_DIR})
  file(
    WRITE "${dir}/.clang-tidy"
    "Checks: '-*,readability-inconsistent-declaration-parameter-name'
WarningsAsErrors: ''
ExtraArgs: ['-Wno-error']
    ")
endforeach()

# --- disable warnings-as-errors for YaFF third-party targets ---
if(MSVC)
  set(_yaff_no_werror /WX-)
else()
  set(_yaff_no_werror -Wno-error)
endif()
function(fptn_yaff_disable_werror dir)
  get_property(subdirs DIRECTORY ${dir} PROPERTY SUBDIRECTORIES)
  foreach(subdir ${subdirs})
    fptn_yaff_disable_werror(${subdir})
  endforeach()
  get_property(targets DIRECTORY ${dir} PROPERTY BUILDSYSTEM_TARGETS)
  foreach(target ${targets})
    get_target_property(target_type ${target} TYPE)
    if(NOT target_type STREQUAL "INTERFACE_LIBRARY")
      set_target_properties(${target} PROPERTIES COMPILE_WARNING_AS_ERROR OFF)
      target_compile_options(${target} PRIVATE ${_yaff_no_werror})
    endif()
  endforeach()
endfunction()
fptn_yaff_disable_werror(${yaff_SOURCE_DIR})
