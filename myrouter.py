#!/usr/bin/env python3

'''
Basic IPv4 router  in Python.
'''
import ipaddress
from switchyard.lib.userlib import *
from switchyard.lib.address import *
from datetime import datetime, timedelta
import sys
import os
import time

class RoutingEntry():
    def __init__(self, prefix, mask, next_hop, interface_name):
        self.prefix = prefix
        self.mask = mask
        self.next_hop = next_hop
        self.interface_name = interface_name


class QueuedPacket():
    def __init__(self, packet, best_match_entry):
        self.packet = packet
        self.attempt_count = 0
        self.attempt_time = 0
        self.best_match_entry = best_match_entry


class Router(object):
    def __init__(self, net):
        self.net = net
        self.interfaces = net.interfaces()
        self.ip_addresses = [intf.ipaddr for intf in self.interfaces]
        self.mac_addresses = [intf.ethaddr for intf in self.interfaces]
        self.cachetable= {}
        self.routingtable = []

  
        for intf in self.interfaces:
            network = ipaddress.ip_network(f"{intf.ipaddr}/{intf.netmask}", strict=False)
            entry = RoutingEntry(network.network_address, network.netmask, None, intf.name)
            self.routingtable.append(entry)


        try:
            with open("forwarding_table.txt") as f:
                for line in f:
                    if not line.strip():
                        continue
                    fields = line.split()
                    prefix = ipaddress.IPv4Address(fields[0])
                    mask = ipaddress.IPv4Address(fields[1])
                    next_hop = ipaddress.IPv4Address(fields[2]) if fields[2] != '-' else None
                    interface_name = fields[3]
                    entry = RoutingEntry(prefix, mask, next_hop, interface_name)
                    self.routingtable.append(entry)
        except Exception as e:
            log_info(f"Error loading forwarding table: {e}")

        for entry in self.routingtable:
            log_info(f"{entry.prefix} {entry.mask} {entry.next_hop} {entry.interface_name}")

    def start(self):
       
        packet_queue = []
        while True:
           
            if packet_queue:
                queued_packet = packet_queue[0]
                port = next((intf for intf in self.interfaces if intf.name == queued_packet.best_match_entry.interface_name), None)
                target_ip = queued_packet.best_match_entry.next_hop or queued_packet.packet[IPv4].dst

                if target_ip in self.cachetable:
                    queued_packet.packet[Ethernet].dst = self.cachetable[target_ip]
                    queued_packet.packet[Ethernet].src = port.ethaddr
                    self.net.send_packet(port, queued_packet.packet)
                    del packet_queue[0]
                elif queued_packet.attempt_count >= 5:
                    del packet_queue[0]
                else:
                    cur_time = time.time()
                    if queued_packet.attempt_count == 0 or (cur_time - queued_packet.attempt_time) > 1:
                        ether = Ethernet(src=port.ethaddr, dst='ff:ff:ff:ff:ff:ff', ethertype=EtherType.ARP)
                        arp = Arp(operation=ArpOperation.Request,
                                  senderhwaddr=port.ethaddr,
                                  senderprotoaddr=port.ipaddr,
                                  targethwaddr='ff:ff:ff:ff:ff:ff',
                                  targetprotoaddr=target_ip)
                        arp_request = ether + arp
                        self.net.send_packet(port, arp_request)
                        queued_packet.attempt_count += 1
                        queued_packet.attempt_time = cur_time

            packet_received = True
            try:
                timestamp, dev, pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                packet_received= False
            except Shutdown:
                break

            if packet_received:
                log_debug("Got a packet: {}".format(str(pkt)))
                log_info("Got a packet: {}".format(str(pkt)))

                if pkt.has_header(IPv4):
                    ipv4_header = pkt[IPv4]
                    if ipv4_header is None :
                        log_info("Invalid IPv4 header ")
                        continue

                    ipv4_header.ttl -= 1
                    best_match = self.find_best_route(ipv4_header.dst)

                    if best_match is None:
                        log_info("No matching entries in the forwarding table for destination IP")
                        continue

                    packet_queue.append(QueuedPacket(pkt, best_match))

                arp_header = pkt.get_header(Arp)
                if arp_header is not None:
                    self.handle_arp(arp_header, dev)

    def find_best_route(self, dst_ip):
        longest_prefix = -1
        best_match = None

        for entry in self.routingtable:
            if int(dst_ip) & int(entry.mask) == int(entry.prefix):
                netaddr = ipaddress.ip_network(f"{entry.prefix}/{entry.mask}")
                if netaddr.prefixlen > longest_prefix:
                    longest_prefix = netaddr.prefixlen
                    best_match = entry

        return best_match

    def handle_arp(self, arp_header, device_name):
        log_info("Received an ARP packet")
        
        
        if arp_header.senderprotoaddr in self.cachetable:
            if arp_header.senderhwaddr != self.cachetable[arp_header.senderprotoaddr]:
                log_info(f"Updating ARP cache for IP {arp_header.senderprotoaddr}")
                self.cachetable[arp_header.senderprotoaddr] = arp_header.senderhwaddr
        else:
            log_info(f"Adding new entry to ARP cache for IP {arp_header.senderprotoaddr}")
            self.cachetable[arp_header.senderprotoaddr] = arp_header.senderhwaddr

        
        log_info("Current ARP table")
        for ip_addr, mac_addr in self.cachetable.items():
            log_info(f" IP address:{ip_addr}, MAC address:{mac_addr}")

        
        if arp_header.operation == ArpOperation.Request:
            for intf in self.interfaces:
                if arp_header.targetprotoaddr == intf.ipaddr:
                    ether_reply = Ethernet()
                    ether_reply.src = intf.ethaddr
                    ether_reply.dst = arp_header.senderhwaddr
                    ether_reply.ethertype = EtherType.ARP
                    
                    arp_reply = Arp(operation=ArpOperation.Reply,
                                    senderhwaddr=intf.ethaddr,
                                    senderprotoaddr=intf.ipaddr,
                                    targethwaddr=arp_header.senderhwaddr,
                                    targetprotoaddr=arp_header.senderprotoaddr)
                    
                    reply_packet = ether_reply + arp_reply
                    self.net.send_packet(device_name, reply_packet)
                    log_info(f"Sent ARP reply from {intf.ipaddr} to {arp_header.senderprotoaddr}")
                    break  


def main(net):
    '''
    Main entry point for router. Just create Router object and get it going.
    '''
    router = Router(net)
    router.start()
    net.shutdown()