cmake_minimum_required(VERSION 3.5)
project(xmss)

set(CMAKE_CXX_STANDARD 11)

include(CMakeHelpers.cmake)

CheckLibrary()

add_library(xmss
        params.c
        hash.c
        fips202.c
        hash_address.c
        randombytes.c
        wots.c
        xmss.c
        xmss_core.c
        xmss_commons.c
        utils.c)

# oid test
add_executable(oid test/oid.c)
target_link_libraries(oid xmss crypto)

# wots test
add_executable(wots test/wots.c)
target_link_libraries(wots xmss crypto)

# xmss test
add_executable(xmss-test test/xmss.c)
target_link_libraries(xmss-test xmss crypto)

# xmss determinism test
add_executable(xmss-determinism test/xmss_determinism.c)
target_link_libraries(xmss-determinism xmss crypto)

# keypair
add_executable(keypair ui/keypair.c)
target_link_libraries(keypair xmss crypto)

# open
add_executable(open ui/open.c)
target_link_libraries(open xmss crypto)

# sign
add_executable(sign ui/sign.c)
target_link_libraries(sign xmss crypto)
