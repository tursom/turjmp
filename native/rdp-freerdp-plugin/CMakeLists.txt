cmake_minimum_required(VERSION 3.16)

project(proxy-turjmp-plugin VERSION 0.1.0 LANGUAGES C)

find_package(PkgConfig REQUIRED)
pkg_check_modules(FREERDP_PROXY_MODULE REQUIRED freerdp-proxy-module)

add_library(proxy-turjmp-plugin SHARED turjmp_plugin.c)
set_target_properties(proxy-turjmp-plugin PROPERTIES
  C_STANDARD 11
  C_STANDARD_REQUIRED ON
  PREFIX ""
  OUTPUT_NAME "proxy-turjmp-plugin"
)
target_include_directories(proxy-turjmp-plugin PRIVATE ${FREERDP_PROXY_MODULE_INCLUDE_DIRS})
target_compile_options(proxy-turjmp-plugin PRIVATE ${FREERDP_PROXY_MODULE_CFLAGS_OTHER})
target_link_directories(proxy-turjmp-plugin PRIVATE ${FREERDP_PROXY_MODULE_LIBRARY_DIRS})
target_link_libraries(proxy-turjmp-plugin PRIVATE ${FREERDP_PROXY_MODULE_LIBRARIES} pthread)
