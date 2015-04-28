
#Skeleton code for programming assignment #2 Part III file called SimpleLoadBalancer.py
from pox.core import core
from pox.openflow import *
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr, IPAddr
log = core.getLogger()
import time
import random

class SimpleLoadBalancer(object):
    def __init__(self, service_ip, server_ips = []): #initialize
        core.openflow.addListeners(self)
	self.service_ip = service_ip
	self.server_ips = server_ips
	self.port_MAC = {}
	self.server = {}

    def _handle_ConnectionUp(self, event): #new switch connection
        self.lb_mac = EthAddr("00:00:00:00:00:0A") #fake mac of load balancer
        self.connection = event.connection
       
	for server_ip in self.server_ips:   #ARP request for each server IP
	    self.send_proxied_arp_request(self.connection, server_ip)

    def update_lb_mapping(self, client_ip): #update load balancing mapping
        server_ip = random.choice(self.server.keys())
	return server_ip

    def send_proxied_arp_reply(self, packet, connection, outport, requested_mac):
        ARP = arp()
      	ARP.opcode = arp.REPLY
	ARP.hwsrc = requested_mac #source MAC address for ARP reply
	ARP.hwdst = packet.payload.hwsrc #destination MAC adrress for ARP reply
	ARP.protosrc = packet.payload.protodst
	log.info("Packet payload ARP......"+str(packet.payload))
	ARP.protodst = packet.payload.protosrc

	ETHERNET = ethernet(type = ethernet.ARP_TYPE, src = ARP.hwsrc, dst = ARP.hwdst)
	ETHERNET.set_payload(ARP)

	msg = of.ofp_packet_out()
	msg.data = ETHERNET.pack()
	msg.actions.append(of.ofp_action_output(port = outport))
	msg.in_port = of.OFPP_NONE
	connection.send(msg)
	log.info("Sending ARP reply...... " + str(ARP))
	
	return

    def send_proxied_arp_request(self, connection, ip):
        ARP = arp()
	ARP.opcode = arp.REQUEST
	ARP.hwsrc = self.lb_mac
	ARP.hwdst = EthAddr("ff:ff:ff:ff:ff:ff")
	ARP.protosrc = self.service_ip
	ARP.protodst = ip

	ETHERNET = ethernet(type = ethernet.ARP_TYPE, src = ARP.hwsrc, dst = ARP.hwdst)
        ETHERNET.set_payload(ARP)

	log.info("Sending ARP request " + str(ARP))

	msg = of.ofp_packet_out()
	msg.data = ETHERNET.pack()
	msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
	msg.in_port = of.OFPP_NONE
	self.connection.send(msg)
	return

    def install_flow_rule_client_to_server(self, connection, outport, client_ip,server_ip, buffer_id=of.NO_BUFFER):
        msg = of.ofp_flow_mod()
	msg.idle_timeout = 10
	msg.buffer_id = None
	
	msg.match.in_port = outport
	msg.match.dl_src = self.client_mac
	msg.match.dl_dst = self.lb_mac
	msg.match.dl_type = ethernet.IP_TYPE
	msg.match.nw_src = client_ip
	msg.match.nw_dst = self.service_ip
	#msg.match.nw_proto = 1

	msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
    	msg.actions.append(of.ofp_action_dl_addr.set_dst(self.server[server_ip][0]))
    	msg.actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac))
	msg.actions.append(of.ofp_action_output(port = self.server[server_ip][1]))
	
        self.connection.send(msg)
        return


    def install_flow_rule_server_to_client(self, connection, outport, server_ip, client_ip, buffer_id=of.NO_BUFFER):
        msg = of.ofp_flow_mod()
    	msg.idle_timeout = 10           
    	msg.buffer_id = None

	msg.match.in_port = self.server[server_ip][1]
	msg.match.dl_src = self.server[server_ip][0]
	msg.match.dl_dst = self.lb_mac
	msg.match.nw_src = server_ip
    	msg.match.nw_dst = client_ip
	#msg.match.nw_proto = 1
    	
	msg.actions.append(of.ofp_action_nw_addr.set_src(self.service_ip))
    	msg.actions.append(of.ofp_action_dl_addr.set_src(self.lb_mac))
	msg.actions.append(of.ofp_action_dl_addr.set_dst(self.client_mac))
    	msg.actions.append(of.ofp_action_output(port = outport))
	
	self.connection.send(msg)

	return

    def _handle_PacketIn(self, event):
        self.event = event
 	packet = event.parsed
        connection = event.connection
        inport = event.port
        if packet.type == packet.ARP_TYPE:
	   
            log.info("ARP received......." + str(packet.payload))
	    self.port_MAC[str(packet.payload.hwsrc)] = inport
	   
	    if packet.payload.opcode == arp.REQUEST:		   
                self.send_proxied_arp_reply(packet, connection, inport, self.lb_mac)
	    elif packet.payload.opcode == arp.REPLY:
		self.server[packet.payload.protosrc] = [packet.payload.hwsrc,event.port]
		#log.info("Server dictionary"+str(self.server_dict))	     	
	       
        elif packet.type == packet.IP_TYPE:
            log.info("IP Packet"+str(packet.IP_TYPE))
	    client_ip = packet.payload.srcip
	    server_ip = self.update_lb_mapping(client_ip) 	
	    
 	    self.client_mac = packet.src
	    log.info("Set Server to client flow")
	    self.install_flow_rule_server_to_client(connection, inport, server_ip, client_ip, buffer_id=of.NO_BUFFER) 
	    log.info("Set Client to server flow")
	    self.install_flow_rule_client_to_server(connection, inport, client_ip, server_ip, buffer_id=of.NO_BUFFER)
        else:
            log.info("Unknown Packet type: %s" % packet.type)
            return
        return
    #launch application with following arguments:
    #example usage: python pox.py SimpleLoadBalancer --ip=10.1.2.3 --servers=10.0.0.4,10.0.0.5,10.0.0.6
def launch(ip, servers):
    log.info("Loading Simple Load Balancer module")
    server_ips = servers.replace(","," ").split()
    server_ips = [IPAddr(x) for x in server_ips]
    service_ip = IPAddr(ip)
    core.registerNew(SimpleLoadBalancer, service_ip, server_ips)
