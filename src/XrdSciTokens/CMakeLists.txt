unset(BUILD_SCITOKENS CACHE)

if(NOT ENABLE_SCITOKENS)
  return()
endif()

if(FORCE_ENABLED)
  find_package(SciTokensCpp REQUIRED)
else()
  find_package(SciTokensCpp)
endif()

if(SciTokensCpp_FOUND)
  set(BUILD_SCITOKENS TRUE CACHE INTERNAL "")
else()
  return()
endif()

set(XrdAccSciTokens XrdAccSciTokens-${PLUGIN_VERSION})

add_library(XrdSciTokensObj
  XrdSciTokensAccess.cc XrdSciTokensHelper.hh
  XrdSciTokensMon.cc    XrdSciTokensMon.hh
)

target_link_libraries(XrdSciTokensObj
  PRIVATE
    XrdUtils
    XrdServer
    ${SCITOKENS_CPP_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
    ${CMAKE_DL_LIBS}
)

target_include_directories(XrdSciTokensObj
  PRIVATE
    vendor/inih
    vendor/picojson
    ${SCITOKENS_CPP_INCLUDE_DIR}
)

set_target_properties(XrdSciTokensObj PROPERTIES POSITION_INDEPENDENT_CODE ON)
if(HAVE_SCITOKEN_CONFIG_SET_STR)
  target_compile_definitions(XrdSciTokensObj
    PRIVATE
      HAVE_SCITOKEN_CONFIG_SET_STR
  )
endif()

add_library(${XrdAccSciTokens} MODULE
  "$<TARGET_OBJECTS:XrdSciTokensObj>"
)
target_link_libraries(${XrdAccSciTokens}
  PRIVATE
    XrdSciTokensObj
)

install(
  TARGETS
    ${XrdAccSciTokens}
  LIBRARY
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
