cmake_minimum_required(VERSION 3.8)
project(uart_miner C ASM CXX)

set(CMAKE_C_STANDARD 11)

#set_source_files_properties(asm/sha2-x64.S PROPERTIES COMPILE_FLAGS "-x assembler-with-cpp")
set_source_files_properties(src/uint256.cpp PROPERTIES COMPILE_FLAGS "-Wno-effc++")
set_source_files_properties(asm/aesb-x64.S PROPERTIES COMPILE_FLAGS "-x assembler-with-cpp")
set(crypto_directory
        crypto/c_blake256.c
        crypto/c_groestl.c
        crypto/c_jh.c
        crypto/c_keccak.c
        crypto/c_skein.c
        crypto/hash.c
        crypto/oaes_lib.c
        crypto/aesb.c
        crypto/aesb-x64.S
        )

set(sha3_directory
        asm/sha2-x64.S
        sha3/sph_keccak.c
        sha3/sph_hefty1.c
        sha3/sph_groestl.c
        sha3/sph_skein.c
        sha3/sph_bmw.c
        sha3/sph_jh.c
        sha3/sph_shavite.c
        sha3/sph_blake.c
        sha3/mod_blakecoin.c
        sha3/sph_luffa.c
        sha3/sph_cubehash.c
        sha3/sph_simd.c
        sha3/sph_echo.c
        sha3/sph_hamsi.c
        sha3/sph_haval.c
        sha3/sph_fugue.c
        sha3/sph_ripemd.c
        sha3/sph_sha2.c
        sha3/sph_sha2big.c
        sha3/sph_shabal.c
        sha3/sph_whirlpool.c
        sha3/gost_streebog.c
        )

set(src_directory
        src/sha2.c
        src/x11.c
        src/cryptonight.c
        src/serial.c
        src/sysinfos.c
        src/util.c
        src/uint256.cpp
        src/communication.c
        )

set(SOURCE_FILES ${src_directory} ${sha3_directory} ${crypto_directory})
add_executable(uart_miner ${SOURCE_FILES} src/uart-miner.c)
target_link_libraries(uart_miner jansson curl ssl pthread)