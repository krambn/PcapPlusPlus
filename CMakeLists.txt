include_directories(Common++/header Common++/src Packet++/header Packet++/src Pcap++/header Pcap++/src /usr/include/netinet)
add_subdirectory(Common++)
add_subdirectory(Packet++)
add_subdirectory(Pcap++)
add_subdirectory(3rdParty/LightPcapNg/LightPcapNg)

