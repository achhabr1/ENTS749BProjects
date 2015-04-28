#Code references: Open source Pyretic libraries, www.csg.ethz.ch, and Mininet documentation
#Upload this script into the Mininet-VM directory ~/pyretic/pyretic/examples
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.examples.proj_dumb_forwarding import dumb_forwarder

class FlowMonitorBlackholeRedirector(DynamicPolicy):
    def __init__(self, threshold_rate, blackhole_port_dict, IPs_and_TCP_ports_to_protect):
        super(FlowMonitorBlackholeRedirector, self).__init__()
        self.threshold_rate = threshold_rate
        self.port_dict = blackhole_port_dict
        self.ips_tcp_ports = IPs_and_TCP_ports_to_protect
        self.untrusted_incoming_traffic_to_check = union([match(inport=self.port_dict['untrusted'], dstip=i, protocol=6, dstport=p) for (i,p) in self.ips_tcp_ports])       
	self.forward = dumb_forwarder(self.port_dict['trusted'],self.port_dict['untrusted']) #initial forwarding scheme 
        ### write your code ###: other useful attributes?
        self.refresh()
        
    def update_policy(self):
        ### write your code ###: update the policy based on current forward and query policies 
       
	self.policy = self.forward + self.dos_check
	pass
    
    def check_redirect(self,counter): ### write your code ###: other attributes?
        ### write your code ###: implement check and redirection
	
	for key in counter:
	   if counter[key] > self.threshold_rate:
	   	self.forward = dumb_forwarder(self.port_dict['untrusted'],self.port_dict['blackhole'])
		print "Suspected DoS:" + str(counter[key])
           else:
		print "Everything Fine::" + str(counter[key])
		self.forward = dumb_forwarder(self.port_dict['trusted'],self.port_dict['untrusted'])
    
	   counter[key] = 0
	   self.update_policy()
	pass
         
    def refresh_query(self):
        ### write your code ###: reset the query checking for suspicious traffic and register the callback function
        self.query = count_packets(1,['srcip','dstip','dstport'])
        self.query.register_callback(self.check_redirect)
	self.dos_check = self.untrusted_incoming_traffic_to_check >> self.query	
	pass

    def refresh(self):
        #refresh query and policy
        self.refresh_query()
        self.update_policy()

