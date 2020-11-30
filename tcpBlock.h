#pragma once

#include <pcap.h>
#include "mac.h"

Mac getMyMac(const char* ifname);
void blockPacket(const u_char* packet, int pktLen, pcap_t* handle, Mac myMac);