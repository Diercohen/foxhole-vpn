cmake_minimum_required(VERSION 3.13)
project(appmodules)

# React Native's own native part (the TurboModules' glue), as its default app setup builds it
include(${REACT_ANDROID_DIR}/cmake-utils/ReactNative-application.cmake)

# Node (nodejs-mobile's libnode.so, fetched by scripts/prepare.mjs into NODE_DIR), started by Core.kt
add_library(node SHARED IMPORTED)
set_target_properties(node PROPERTIES IMPORTED_LOCATION ${NODE_DIR}/bin/${ANDROID_ABI}/libnode.so)
add_library(foxhole SHARED node/start.cpp)
target_link_libraries(foxhole node log)
