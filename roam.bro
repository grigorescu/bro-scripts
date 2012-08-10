##! roam.bro
##! 
##! This script collects IP-to-MAC mappings (and vice versa) of machines
##! that may have more than one IP address over time due to a DHCP server
##! in the network.
##! 
##! When keeping per-IP-address state, it could well be that the address
##! becomes invalid because the client's DHCP lease expired or because it
##! received a new IP address after rejoining the network. Ideally, this
##! state would roam with the user. But many Bro script data structures
##! use per-address indices and would mechanistically instantiate state
##! for a new client even though it merely reappeared under a new IP
##! address. To incorporate the notion of roaming, roam.bro makes
##! available two data structures that script writers can use:
##! 
##!     global ip_to_mac: table[addr] of string
##!         &read_expire = alias_expiration &synchronized;
##! 
##!     global mac_to_ip: table[string] of set[addr]
##!         &read_expire = alias_expiration &synchronized;
##! 
##! Event handlers for the dhcp_ack and arp_reply events populate
##! these tables. For example, the sidejacking script (see below) makes
##! use of roam.bro to test whether a certain client IP address is an
##! alias of another IP address:
##! 
##!     function is_aliased(client: addr, ctx: cookie_context) : bool
##!     {
##!         if (client in Roam::ip_to_mac)
##!         {
##!             local mac = Roam::ip_to_mac[client];
##!             if (mac == ctx$mac && mac in Roam::mac_to_ip
##!                 && client in Roam::mac_to_ip[mac])
##!                 return T;
##!         }
##! 
##!         return F;
##!     }
##! 
##! If the two table are not accessed for more than the
##! alias_expiration, the entry will expire. It is possible to
##! redefine the expiration interval:
##! 
##!     redef Roam::alias_expiration = 7 days;
##! 
##! Author: Matthias Vallentin

module Roam;

export
{
    # Time after which observed MAC to IP mappings (and vice versa) expire.
    const alias_expiration = 1 day &redef;

    global ip_to_mac: table[addr] of string
        &read_expire = alias_expiration &synchronized;

    global mac_to_ip: table[string] of set[addr]
        &read_expire = alias_expiration &synchronized;
}

# Collect IP-to-MAC mappings and vice versa from DHCP ACKs.
event DHCP::dhcp_ack(c: connection, msg: dhcp_msg, mask: addr,
		router: dhcp_router_list, lease: interval, serv_addr: addr)
{
    local ip = msg$yiaddr;
    local mac = msg$h_addr;

    if (ip !in ip_to_mac)
        ip_to_mac[ip] = mac;

    if (mac !in mac_to_ip)
        mac_to_ip[mac] = set() &mergeable;

    add mac_to_ip[mac][ip];
}

# Collect IP-to-MAC mappings and vice versa from ARP replies.
event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string,
    TPA: addr, THA: string)
{
    local ip = SPA;
    local mac = mac_src;

    if (ip !in ip_to_mac)
        ip_to_mac[ip] = mac;

    if (mac !in mac_to_ip)
        mac_to_ip[mac] = set() &mergeable;

    add mac_to_ip[mac][ip];
}
