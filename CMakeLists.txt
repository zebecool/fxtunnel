project ("fxtunnel")

cmake_minimum_required (VERSION 2.8)

set(CMAKE_BUILD_TYPE Debug)
# set(CMAKE_BUILD_TYPE Release)

if(WIN32)
    set(OPENSSL "C:/Program Files (x86)/OpenSSL-Win32")
    include_directories( ${OPENSSL}/include )
    link_directories( ${OPENSSL}/lib )

    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "C:/ppforward_workspace/fxtunnel/bin")
    # set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SUBSYSTEM:WINDOWS")
    # set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /ENTRY:WinMainCRTStartup")
    # set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SUBSYSTEM:CONSOLE")
    ADD_EXECUTABLE (fxtunnel WIN32 main.cpp fxtunnel.cpp sslserver.cpp sslclient.cpp agent.cpp connector.cpp resources.rc)
    #install(TARGETS fxtunnel )
elseif(UNIX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -W -Wno-deprecated -Wno-attributes -Wno-missing-field-initializers -Wno-format-truncation")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -g3 -ggdb3 -rdynamic -std=c++17 -DDEBUG -Wno-sign-compare -Wno-unused-parameter -Wno-sequence-point")
    # set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -g3 -ggdb3 -rdynamic -std=c++17 -DDEBUG -Wno-deprecated -Wno-literal-suffix -Wno-unused-variable -Wno-write-strings -Wno-delete-non-virtual-dtor -Wno-unused-parameter -Wno-conversion-null -Wno-unused-but-set-variable -Wno-unused-function -Wno-format -Wno-extra")
    set(CMAKE_CXX_FLAGS_RELEASE "-O -g -std=c++17 ")

    set(OPENSSL "/usr/local/ssl")
    include_directories( ${OPENSSL}/include )
    link_directories( ${OPENSSL}/lib64 )
    
    ADD_EXECUTABLE(fxtunnel main.cpp fxtunnel.cpp sslserver.cpp sslclient.cpp agent.cpp connector.cpp)
    TARGET_LINK_LIBRARIES(fxtunnel pthread crypto ssl)

    set(CMAKE_INSTALL_PREFIX /fxtunnel)
    INSTALL(TARGETS fxtunnel RUNTIME DESTINATION .)
    # INSTALL(FILES fxtunnel.conf server.crt server.key DESTINATION .)
endif()

