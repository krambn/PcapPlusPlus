set(CMAKE_CXX_FLAGS "-DLINUX")
include_directories(../3rdParty/LightPcapNg/LightPcapNg/include)
add_library(pcap++Pcap SHARED 
src/DpdkDevice.cpp
src/NetworkUtils.cpp
src/PcapDevice.cpp
src/PcapFileDevice.cpp
src/PcapFilter.cpp
src/PcapLiveDevice.cpp
src/PcapLiveDeviceList.cpp
src/PcapRemoteDevice.cpp
src/PcapRemoteDeviceList.cpp
src/PfRingDevice.cpp
src/PfRingDeviceList.cpp
src/WinPcapLiveDevice.cpp
src/DpdkDeviceList.cpp
)
