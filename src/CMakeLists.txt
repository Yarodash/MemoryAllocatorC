set(CMAKE_C_EXTENSIONS off)
set(CMAKE_C_STANDARD 17)

if(CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang)$")
    add_compile_options(-Wall -Wextra -Wconversion -pedantic -g -O0)
endif()

add_executable(prog main.c memory_manage.c)

add_compile_definitions(_XOPEN_SOURCE=700)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_compile_definitions(_DEFAULT_SOURCE)
endif()

add_custom_target(run "./prog")
