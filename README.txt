/ ########## code structure overview and design logic ####### /

Assignment 2 follows assignment 1 logic, adding NAT for internal external address translation and additional TCP packet handling. 

/ ******* NAT translation ****** /
1. Outbound packet and sent to me: 
1.1. icmp packet: send back icmp directly. No NAT required for this part. Only several address changes and other parameters such as checksum are needed for this part. 

1.2. tcp packet: send back icmp type 3 port unreachable. No NAT required. Form icmp t3 port unreachable (type 3 code 3) same as a1. 

2. Outbound packet and not sent to me: 
2.1. icmp packet: forward the packet to the destination address. NAT is required to translate the internal address to external address. First we need to check the NAT, if the mapping is not found, we add the new mapping to our NAT table. Do the ARP as a1, cache the ARP request and send the packet when the address is found. 

2.2. tcp packet: forward the packet to the destination. NAT is required as icmp. Besides, we need to check tcp connection. If the connection is found, we can record the tcp state and forward the packet; otherwise we add the new connection. 

3. Inbound packet: 
3.1. icmp packet: NAT is required to check the mapping. If the server address has been recorded, we can get the mapped inner address and send the packet. Otherwise the packet should be dropped. 

3.2. tcp packet: The same as icmp packet. Besides, if the mapping is not found, we need to do the unsolicited checking. We cache the inbound tcp packet; wait for 6 seconds until an outbound packet is received with the same mapping, then we send an icmp t3; otherwise we drop the packet. 

/############ important functions  ##################/
sr_nat_lookup_external: look up from external packet
sr_nat_lookup_internal: look up from internal packet
sr_nat_insert_mapping: insert the new mapping to the nat table
sr_nat_lookup_tcp_con: look up the tcp connection
sr_nat_insert_tcp_con: insert tcp connection
generate_icmp_identifier: generate icmp identifier from 0
generate_port: generate tcp port number from 1024


/############# what's left  ####################/
The part which hasn't been fully implemented is unsolicited inbound packet. I have written a cache to store the inbound tcp packet and use timeout to send icmp t3 packet out to the src address. But scrutiny is still needed since it is not working correctly. 

