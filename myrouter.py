#!/usr/bin/env python3

import time
import switchyard
from switchyard.lib.userlib import *
from switchyard.lib.address import *
import ipaddress
from collections import deque

class RoutingTableEntry:
    def __init__(self, network, mask, next_hop, interface):
        self.network = ipaddress.IPv4Network(f"{network}/{mask}", strict=False)
        self.next_hop = next_hop
        self.interface = interface

class ARPQueueItem:
    def __init__(self, packet, interface, next_hop_ip, retries=0, last_sent_time=None):
        self.packet = packet
        self.interface = interface
        self.next_hop_ip = next_hop_ip
        self.retries = retries
        self.last_sent_time = last_sent_time if last_sent_time else time.time()

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.routing_table = []
        self.load_routing_table()
        self.interfaces = self.net.interfaces()
        self.interface_info = {
            iface.name: {
                'ip': iface.ipaddr,
                'hw': iface.ethaddr
            } for iface in self.interfaces
        }
        self.arp_cache = {}
        self.arp_queue = deque()

    def load_routing_table(self):
        with open("forwarding_table.txt", "r") as f:
            for line in f:
                network, mask, next_hop, interface = line.strip().split()
                self.routing_table.append(RoutingTableEntry(network, mask, next_hop, interface))
        
        # Add directly connected networks
        for iface in self.net.interfaces():
            self.routing_table.append(RoutingTableEntry(
                str(iface.netmask), 
                str(iface.netmask), 
                "0.0.0.0", 
                iface.name
            ))

    def find_best_match(self, dest_ip):
        best_match = None
        longest_prefix = -1
        dest_ip_addr = ipaddress.IPv4Address(dest_ip)
        
        for entry in self.routing_table:
            if dest_ip_addr in entry.network:
                if entry.network.prefixlen > longest_prefix:
                    longest_prefix = entry.network.prefixlen
                    best_match = entry
        
        return best_match

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, iface_name, packet = recv
        eth_hdr = packet.get_header(Ethernet)
        ip_hdr = packet.get_header(IPv4)
        
        if eth_hdr is None or ip_hdr is None:
            log_debug("Received a non-IP packet")
            return
        
        if eth_hdr.dst != "ff:ff:ff:ff:ff:ff" and eth_hdr.dst != self.interface_info[iface_name]['hw']:
            log_debug("Ignored packet not destined for this router's MAC address")
            return
        
        if ip_hdr.dst in [iface['ip'] for iface in self.interface_info.values()]:
            log_debug("Packet destined for this router, ignored")
            return
        
        match_entry = self.find_best_match(ip_hdr.dst)
        if match_entry is None:
            log_debug("No matching route found, packet dropped")
            return
        
        ip_hdr.ttl -= 1
        if ip_hdr.ttl <= 0:
            log_debug("TTL expired, packet dropped")
            return
        
        if match_entry.next_hop == "0.0.0.0":
            next_hop_ip = ip_hdr.dst
        else:
            next_hop_ip = match_entry.next_hop
        
        if next_hop_ip in self.arp_cache:
            self.forward_packet(packet, match_entry, next_hop_ip)
        else:
            self.send_arp_request(packet, match_entry, next_hop_ip)

    def forward_packet(self, packet, match_entry, next_hop_ip):
        next_hop_mac = self.arp_cache[next_hop_ip]
        next_hop_interface = self.net.interface_by_name(match_entry.interface)
        
        new_eth_hdr = Ethernet()
        new_eth_hdr.src = self.interface_info[match_entry.interface]['hw']
        new_eth_hdr.dst = next_hop_mac
        new_eth_hdr.ethertype = EtherType.IPv4
        
        new_packet = new_eth_hdr + packet[1:]
        self.net.send_packet(match_entry.interface, new_packet)

    def send_arp_request(self, packet, match_entry, next_hop_ip):
        next_hop_interface = self.net.interface_by_name(match_entry.interface)
        arp_request = create_ip_arp_request(
            senderhwaddr=self.interface_info[match_entry.interface]['hw'],
            senderprotoaddr=self.interface_info[match_entry.interface]['ip'],
            targetprotoaddr=next_hop_ip
        )
        self.net.send_packet(match_entry.interface, arp_request)
        self.arp_queue.append(ARPQueueItem(packet, match_entry, next_hop_ip))

    def process_arp_queue(self):
        now = time.time()
        to_remove = []
        
        for item in self.arp_queue:
            if now - item.last_sent_time >= 1:
                if item.retries < 5:
                    self.send_arp_request(item.packet, item.match_entry, item.next_hop_ip)
                    item.retries += 1
                    item.last_sent_time = now
                else:
                    to_remove.append(item)
        
        for item in to_remove:
            self.arp_queue.remove(item)

    def handle_arp_reply(self, arp_reply):
        sender_ip = arp_reply.senderprotoaddr
        sender_mac = arp_reply.senderhwaddr
        self.arp_cache[sender_ip] = sender_mac
        
        to_remove = []
        for item in self.arp_queue:
            if item.next_hop_ip == sender_ip:
                self.forward_packet(item.packet, item.match_entry, sender_ip)
                to_remove.append(item)
        
        for item in to_remove:
            self.arp_queue.remove(item)

    def start(self):
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
                self.handle_packet(recv)
            except NoPackets:
                pass
            except Shutdown:
                break
            
            self.process_arp_queue()
        
        self.stop()

    def stop(self):
        self.net.shutdown()

def main(net):
    router = Router(net)
    router.start()