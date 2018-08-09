set(CMAKE_CXX_FLAGS "-DLINUX")
include_directories(header src /usr/include/netinet)
add_library(pcap++Common SHARED 
src/IpAddress.cpp
src/IpUtils.cpp
src/Logger.cpp
src/MacAddress.cpp
src/PcapPlusPlusVersion.cpp
src/SystemUtils.cpp
src/TablePrinter.cpp
)
