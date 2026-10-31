#======================== Unit tests configuration ============================#
# Unit tests of SAes module. Registered in module CMakeLists.txt by
# UnitTesting_AddPath() and created by UnitTesting_Generate() in "UnitTest"
# build (see EmBi_Platform/CMake/UnitTesting/README.md).

get_filename_component(SAES_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
get_filename_component(MCAL_DIR "${SAES_DIR}/.." ABSOLUTE)

# SAes.c checks the SAES peripheral in every function (the lines without it are
# STM32H503, H523, H543, H562, H563, H5E4, H5E5 and only return the error value),
# SAes_Reg.c holds the register access. RCC (peripheral clock), NVIC (interrupt line)
# and RNG (side-channel countermeasures) are mocked by CMock, the SAES registers are
# emulated by RegMem.
UnitTesting_Add_Test(
    NAME            SAes
    TEST_SOURCE     Test_SAes.c
    UUT_SOURCES     ${SAES_DIR}/SAes.c
                    ${SAES_DIR}/SAes_Reg.c
    MOCK_HEADERS    ${MCAL_DIR}/Rcc/Rcc_Port.h
                    ${MCAL_DIR}/Nvic/Nvic_Port.h
                    ${MCAL_DIR}/Rng/Rng_Port.h
    INCLUDE_DIRS    ${SAES_DIR}
                    ${MCAL_DIR}/Rcc
                    ${MCAL_DIR}/Nvic
                    ${MCAL_DIR}/Rng
    LINK_LIBS       ut_RegMem                           # Registers in host memory
                    ut_CmsisHost                        # CMSIS core intrinsics on host
    FORCE_INCLUDES  ${UNIT_TESTING_CMSIS_HOST_HEADER}   # Replaces cmsis_gcc.h
    HOST_LIBS       Ral_Lib                             # ST LL compiled for host
    COVERAGE_EXCLUDE ".*/Ral/.*"
    RUN_SERIAL
)
