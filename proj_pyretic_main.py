#Code references: Open source Pyretic libraries, www.csg.ethz.ch, and Mininet documentation
#Upload this script into the Mininet-VM directory ~/pyretic/pyretic/examples; run it as the main pyretic module
#Run this script using the command: $ pyretic.py pyretic.examples.proj_pyretic_main.py
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.virt import *

#CHECK THE IMPORTS LISTED BELOW
from pyretic.modules.gateway_forwarder import gateway_forwarder
from pyretic.modules.mac_learner import mac_learner
from pyretic.modules.arp import ARP
from pyretic.examples.proj_dumb_forwarding import dumb_forwarder
from pyretic.examples.proj_flow_monitor_blackhole import FlowMonitorBlackholeRedirector
from pyretic.examples.proj_firewall import fw
from pyretic.vdef.proj_split_gateway import split_gateway

class vgateway(DynamicPolicy):
    def __init__(self,pol):
        super(vgateway,self).__init__(virtualize(pol, split_gateway(self)))

def setup(num_internet_hosts=253, num_dmz_servers=1, num_internal_hosts=2):
    #-----------------
    #Network breakdown (the virtual components in Pyretic)
    internal_net_edge = [1000]
    gateway = [1001]
    flow_monitor_blackhole_redirector = [1002]
    firewall = [1003]
    internet_edge =  [1004] 
    
    #-----------------
    #IP subnets
    internal_prefix = '10.1.1.'
    internet_prefix = '10.1.2.'
    prefix_len = 24
    internal_cidr = internal_prefix + '0/' + str(prefix_len)
    internet_cidr = internet_prefix + '0/' + str(prefix_len)
    
    #-----------------
    #End hosts and servers
    internal_ip_to_macs = {IP(internal_prefix+str(i)) : MAC('00:00:00:00:00:0'+str(i)) for i in range(1,1+num_internal_hosts+num_dmz_servers)}
    internet_ip_to_macs = {IP(internet_prefix+str(i)) : MAC('00:00:00:00:00:04') for i in range(1,1+num_internet_hosts)}  
    host_ip_to_macs = dict(internal_ip_to_macs.items() + internet_ip_to_macs.items())
    
    print "Third Arguement:" + str(host_ip_to_macs)
    #-----------------
    #Parameters for flow monitor and blackhole redirector.
    #Threshold rate of packets belonging to the same (srcip,dstip,dstport) flow.
    #If this rate is surpassed, the flow is suspected to be a DoS attack; then redirect flow to the blackhole host.
    threshold_rate = 5 #packets per sec (you can change this if you want to check)
    blackhole_port_dict = {'untrusted' : 2, 'trusted' : 1, 'blackhole' : 3} #see Figure 2 in the project description
    ips_and_tcp_ports_to_protect = [("10.1.1.3",80)] #protect the Apache server
    
    #-----------------
    #Parameters for the stateful firewall
    firewall_port_dict = {'untrusted' : 2, 'trusted' : 1} #see Figure 2 in project description
    whitelist = set([])
    for i in internal_ip_to_macs.keys():
        for j in internet_ip_to_macs.keys():
            internal_ip = str(i)
            internet_ip = str(j)
	    if (internal_ip == '10.1.1.3'):
                whitelist.add((internal_ip,internet_ip))
	        whitelist.add((internet_ip,internal_ip))
	    else:
		whitelist.add((internal_ip,internet_ip))
	    ### write your code ###: Build whitelist of IP addresses (see how firewall expects it)
    print "Firewall whitelist:"
    print whitelist
    
    #-----------------
    #Define policies
    ### write your code ###: internal network edge policy?
    internal_network_edge_policy = mac_learner()
    ### write your code ###: gateway policy?
    gateway_policy = gateway_forwarder(internal_cidr,internet_cidr,host_ip_to_macs)
    ### write your code ###: blackhole host policy?
    blackhole_policy = FlowMonitorBlackholeRedirector(threshold_rate, blackhole_port_dict, ips_and_tcp_ports_to_protect)
    ### write your code ###: firewall policy? Note that besides the IP addresses in the firewall whitelist, the firewall policy should let ARP packets reach the gateway (hint: use 'if_')
    
    ### write your code ###: internet edge policy???
    internet_edge_policy = mac_learner()
    #Commands to do initial test of policies for firewall and blackhole
    firewall_policy = if_(ARP,passthrough,fw(whitelist)) >> dumb_forwarder(firewall_port_dict['trusted'],firewall_port_dict['untrusted']) 
   

    #-----------------
    ### write your code ###: return ? --> Combine the policies! (Hint: check gateway_3switch_example_basic.py in the ~/pyretic/pyretic/examples directory)
    return((switch_in(internal_net_edge) >> internal_network_edge_policy) +
           (switch_in(gateway) >> gateway_policy) + 
	   (switch_in(flow_monitor_blackhole_redirector) >> blackhole_policy) +
	   (switch_in(firewall) >> firewall_policy) +
	   (switch_in(internet_edge) >> internet_edge_policy))
    #return internal_network_edge_policy + gateway_policy + blackhole_policy + internet_edge_policy + firewall_policy
    #return dumb_forwarder(1,4)
def main():
    return vgateway(setup())


