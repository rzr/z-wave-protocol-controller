add_library(zwave_tx_groups src/zwave_tx_groups.cpp
                            src/zwave_tx_groups_internal.cpp)

target_include_directories(
  zwave_tx_groups
  PUBLIC include
  PRIVATE src)

target_link_libraries(zwave_tx_groups PRIVATE zwave_controller unify)
install(TARGETS zwave_tx_groups LIBRARY DESTINATION lib)

if(BUILD_TESTING)
  target_add_mock(zwave_tx_groups)

  add_subdirectory(test)
endif()
