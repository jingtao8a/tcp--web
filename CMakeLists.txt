cmake_minimum_required(VERSION 3.7)
project(tcp--web)

include_directories(
        ${PROJECT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/src/xnet_app
        ${PROJECT_SOURCE_DIR}/src/xnet_tiny
        ${PROJECT_SOURCE_DIR}/lib/xnet
        ${PROJECT_SOURCE_DIR}/lib/npcap/Include
)


add_executable(${PROJECT_NAME} ./lib/xnet/pcap_device.c src/app.c)
add_subdirectory(src/xnet_tiny)
add_subdirectory(src/xnet_app)
target_link_libraries(${PROJECT_NAME} xnet_tiny xnet_app)


# add_executable(test1 ./test/test1.c)