#===================== Integration tests configuration ========================#
# Integration tests of SAes module on target. Registered in module CMakeLists.txt
# by IntegrationTesting_AddPath() and created by IntegrationTesting_Generate() in
# "IntegrationTest" build (see EmBi_Platform/CMake/IntegrationTesting/README.md).
#
# The test set is independent - target interface (entry point, initialization,
# fault handlers, system reset) is implemented by ItTarget_SAes.c and
# all libraries of the firmware are listed here.
#
# The firmware is flashed and run on the board of the IT agent.

# StartUp calls BspMain() - the entry point of the test firmware is provided by
# the test set (BspMain.h, ItTarget_SAes.c)
if(NOT TARGET BspMain_Lib)
    add_library(BspMain_Lib INTERFACE)
    target_include_directories(BspMain_Lib INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
endif()

IntegrationTesting_Add_Test(
    NAME            SAes
    TEST_SOURCE     ItTest_SAes.c
    SOURCES         ItTarget_SAes.c     # Target interface of the test set
    LINK_LIBS       StartUp_Lib         # Startup code (calls BspMain)
                    Nvic_Lib            # Fault handlers, system reset (ItTarget)
                    Rng_Lib             # SAES side-channel countermeasures dependency
                    SAes_Lib
    TIMEOUT         60
)
