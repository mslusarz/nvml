#todo: --localize-hidden, cstyle, move to ..
include(CheckCCompilerFlag)
include(CheckCSourceCompiles)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
	message(FATAL_ERROR "Only 64-bit platforms are supported.")
endif()

if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build, options are: Debug Release." FORCE)
endif()

set(CMAKE_C_FLAGS_RELEASE "-O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2")
set(CMAKE_C_FLAGS_DEBUG "-O0 -ggdb -DDEBUG")

set(pmem-src libpmem.c pmem.c ../common/util.c ../common/out.c)
add_library(pmem-common OBJECT ${pmem-src})

target_include_directories(pmem-common PUBLIC ../include)
target_include_directories(pmem-common PRIVATE ../common)

target_compile_definitions(pmem-common PRIVATE -DNO_LIBPTHREAD)

if(EXISTS "${CMAKE_SOURCE_DIR}/.git")
	execute_process(COMMAND git describe OUTPUT_VARIABLE SRCVERSION WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} OUTPUT_STRIP_TRAILING_WHITESPACE)
else()
	execute_process(COMMAND cat .version OUTPUT_VARIABLE SRCVERSION WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} OUTPUT_STRIP_TRAILING_WHITESPACE)
endif()
target_compile_definitions(pmem-common PRIVATE -DSRCVERSION="${SRCVERSION}")

target_compile_options(pmem-common PRIVATE -std=gnu99)
target_compile_options(pmem-common PRIVATE -fPIC)
target_compile_options(pmem-common PRIVATE -pthread)
target_compile_options(pmem-common PRIVATE -fno-common)
target_compile_options(pmem-common PRIVATE -Wall)
target_compile_options(pmem-common PRIVATE -Werror)
target_compile_options(pmem-common PRIVATE -Wmissing-prototypes)
target_compile_options(pmem-common PRIVATE -Wpointer-arith)
target_compile_options(pmem-common PRIVATE -Wunused-macros)
target_compile_options(pmem-common PRIVATE -Wmissing-field-initializers)
target_compile_options(pmem-common PRIVATE -Wsign-conversion)
target_compile_options(pmem-common PRIVATE -Wsign-compare)

set(SAFE_CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS}")
set(CMAKE_REQUIRED_FLAGS "-Wconversion")
check_c_source_compiles("long int random(void); char test(void); char test(void){char a = 0; char b = 'a'; char ret = random() == 1 ? a : b; return ret;} int main(){return 0;}" HAS_WORKING_Wconversion)
set(CMAKE_REQUIRED_FLAGS "${SAFE_CMAKE_REQUIRED_FLAGS}")
if(HAS_WORKING_Wconversion)
	target_compile_options(pmem-common PRIVATE -Wconversion)
endif()

check_c_compiler_flag(-Wunreachable-code-return HAS_Wunreachable-code-return)
if(HAS_Wunreachable-code-return)
	target_compile_options(pmem-common PRIVATE -Wunreachable-code-return)
endif()

check_c_compiler_flag(-Wmissing-variable-declarations HAS_Wmissing-variable-declarations)
if(HAS_Wmissing-variable-declarations)
	target_compile_options(pmem-common PRIVATE -Wmissing-variable-declarations)
endif()

message("${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
add_library(pmem-shared SHARED $<TARGET_OBJECTS:pmem-common>)
set_target_properties(pmem-shared PROPERTIES VERSION 1.0.0 SOVERSION 1)
set_target_properties(pmem-shared PROPERTIES OUTPUT_NAME pmem)
target_link_libraries(pmem-shared -Wl,-z,relro -Wl,--fatal-warnings -Wl,--warn-common -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/libpmem.map)

add_library(pmem-static STATIC $<TARGET_OBJECTS:pmem-common>)
set_target_properties(pmem-static PROPERTIES OUTPUT_NAME pmem)



#GET_PROPERTY(objects TARGET pmem-common PROPERTY SOURCES)
#message("o: ${objects}")
#add_custom_command(OUTPUT libpmem2.o COMMAND ld -o libpmem2.o -r ${objects})


#add_custom_command(OUTPUT libpmem2.map COMMAND sed -n 's/^\t*\([a-zA-Z0-9_]*\);$/-G \1/p' ${CMAKE_CURRENT_SOURCE_DIR}/libpmem.map DEPENDS libpmem.map)
#add_custom_command(OUTPUT libpmem2.o COMMAND objcopy --localize-hidden `cat libpmem2.map` libpmem.a libpmem2.o DEPENDS libpmem.a libpmem2.map)
add_custom_command(OUTPUT libpmem2.o COMMAND objcopy --localize-hidden -G pmem_map -G pmem_unmap -G pmem_is_pmem -G pmem_persist -G pmem_msync -G pmem_flush -G pmem_drain -G pmem_has_hw_drain -G pmem_check_version -G pmem_errormsg -G pmem_memmove_persist -G pmem_memcpy_persist -G pmem_memset_persist -G pmem_memmove_nodrain -G pmem_memcpy_nodrain -G pmem_memset_nodrain libpmem.a libpmem2.o DEPENDS libpmem.a)
add_custom_command(OUTPUT libpmem2.a COMMAND ar rv libpmem2.a libpmem2.o DEPENDS libpmem2.o)
add_custom_target(pmem2 ALL DEPENDS libpmem2.a)

#ADD_CUSTOM_COMMAND(TARGET pmem2 POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy libpmem.a libpmem2.a)


install(FILES ../include/libpmem.h DESTINATION include/)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
	install(TARGETS pmem-shared pmem-static
		LIBRARY DESTINATION lib${LIB_SUFFIX}
		ARCHIVE DESTINATION lib${LIB_SUFFIX})
elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
	install(TARGETS pmem-shared pmem-static
		LIBRARY DESTINATION lib${LIB_SUFFIX}/nvml_debug
		ARCHIVE DESTINATION lib${LIB_SUFFIX}/nvml_debug)
else()
	message(FATAL_ERROR "CMAKE_BUILD_TYPE has invalid value. Possible values: Debug Release.")
endif()

