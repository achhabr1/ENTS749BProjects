#Code references: Open source Pyretic libraries, www.csg.ethz.ch, and Mininet documentation
#Upload this script into the directory: ~/pyretic/pyretic/vdef
#As an example, check the split_gateway.py script in the directory ~/pyretic/pyretic/vdef
from pyretic.lib.corelib import *
from pyretic.lib.virt import *

class split_gateway(vdef): 
    def __init__(self, redo):
        super(split_gateway,self).__init__()

        def push_vloc(switch,inport):
            return push(vswitch=switch,vinport=inport,voutport=-1)

        self.ingress_policy = if_(match(switch=1),
               push(vtag='ingress') >> (                                
               #At OpenFlow switch, internal network side. Pretend we are virtual switch 1000.
               (match(at=None, inport=1) >> push_vloc(1000,1)) + #host h1
               (match(at=None, inport=2) >> push_vloc(1000,2)) + #host h2
               (match(at=None, inport=3) >> push_vloc(1000,3)) + #HTTP server (h3)
               #At OpenFlow switch, blackhole host side. Pretend we are virtual switch 1002 
               (match(at=None, inport=5) >> push_vloc(1002,3)) +
               
               #At OpenFlow switch, imaginary side close to the internal network (mac learner virtual switch component).
               (match(at="vswitch 1000, vinport 4") >> push_vloc(1000,4) >> pop("at")) +
               (match(at="vswitch 1001, vinport 1") >> push_vloc(1001,1) >> pop("at")) +
	       (match(at="vswitch 1001, vinport 2") >> push_vloc(1001,2) >> pop("at")) +
	       (match(at="vswitch 1002, vinport 1") >> push_vloc(1002,1) >> pop("at")) +
	       (match(at="vswitch 1002, vinport 2") >> push_vloc(1002,2) >> pop("at")) +
	       (match(at="vswitch 1003, vinport 1") >> push_vloc(1003,1) >> pop("at")) +
	       (match(at="vswitch 1003, vinport 2") >> push_vloc(1003,2) >> pop("at")) +
	       (match(at="vswitch 1004, vinport 1") >> push_vloc(1004,1) >> pop("at")) +
	       ### write your code ###: complete the other vlocs (see Figure 2 in the project description)
               #......................
              
               #At OpenFlow switch, Internet side. Pretend we are virtual switch 1004.
               (match(at=None, inport=4) >> push_vloc(1004,2))), passthrough)

        self.fabric_policy = (
            #Destined to the internal network side
            (match(vswitch=1000, voutport=1) >> fwd(1)) +
            (match(vswitch=1000, voutport=2) >> fwd(2)) +
            (match(vswitch=1000, voutport=3) >> fwd(3)) +
            
            #If we are destined to a virtual switch, then push another header that says which virtual switch we are at.
            (match(vswitch=1000, voutport=4) >> push(at="vswitch 1001, vinport 1")) +
	    (match(vswitch=1001, voutport=1) >> push(at="vswitch 1000, vinport 4")) +
	    (match(vswitch=1001, voutport=2) >> push(at="vswitch 1002, vinport 1")) +
	    (match(vswitch=1002, voutport=1) >> push(at="vswitch 1001, vinport 2")) +
	    (match(vswitch=1002, voutport=2) >> push(at="vswitch 1003, vinport 1")) +
	    (match(vswitch=1003, voutport=1) >> push(at="vswitch 1002, vinport 2")) +
	    (match(vswitch=1003, voutport=2) >> push(at="vswitch 1004, vinport 1")) +
	    (match(vswitch=1004, voutport=1) >> push(at="vswitch 1003, vinport 2")) +
            ### write your code here ###: complete the other header pushers (see Figure 2 in the project description)
            #......................
            
            #Destined to the blackhole host side
            (match(vswitch=1002, voutport=3) >> fwd(5)) +
            #Destined to the Internet side
            (match(vswitch=1004, voutport=2) >> fwd(4))
            )
            
        self.egress_policy = pop_vheaders >> \
            if_(match(at=None), passthrough, recurse(redo))

    def make_vmap(self):
        mapping = vmap()
        topo = self.underlying.topology.copy()
        try:
            topo.remove_node(1)

            for u, attrs in topo.nodes(data=True):
                ports = attrs['ports']
                for port in ports:
                    l = Location(u,port)
                    mapping.d2u[l] = [l]
        except:
            pass
        mapping.d2u[Location(1000,1)] = [Location(1,1)] #virtual port 1 of virtual switch 1000 is mapped to physical port 1 of physical switch 1
        mapping.d2u[Location(1000,2)] = [Location(1,2)]
        mapping.d2u[Location(1000,3)] = [Location(1,3)]
        mapping.d2u[Location(1000,4)] = [Location(1,None)] #None physical port because virtual port does not map to any physical port
        mapping.d2u[Location(1001,1)] = [Location(1,None)]
        mapping.d2u[Location(1001,2)] = [Location(1,None)]
        mapping.d2u[Location(1002,1)] = [Location(1,None)]
        mapping.d2u[Location(1002,2)] = [Location(1,None)]
        mapping.d2u[Location(1002,3)] = [Location(1,5)]
        mapping.d2u[Location(1003,1)] = [Location(1,None)]
        mapping.d2u[Location(1003,2)] = [Location(1,None)]
        mapping.d2u[Location(1004,1)] = [Location(1,None)]
        mapping.d2u[Location(1004,2)] = [Location(1,4)]
        return mapping

    def set_network(self,network):
        self.underlying = network
        self.derived = self.DerivedNetwork(self.underlying)
        self.derived.topology = self.underlying.topology.copy()
        try:
            #REMOVE OPENFLOW PHYSICAL SWITCH ONTO WHICH VIRTUAL SWITCHES WILL BE MAPPED
            self.derived.topology.remove_node(1)
            self.derived.inherited.remove(1)
            
            #ADD VIRTUAL SWITCHES
            self.derived.topology.add_node(1000, ports={i: Port(i) for i in range(1,4+1)})
            self.derived.topology.add_node(1001, ports={i: Port(i) for i in range(1,2+1)})
            self.derived.topology.add_node(1002, ports={i: Port(i) for i in range(1,3+1)}) 
            self.derived.topology.add_node(1003, ports={i: Port(i) for i in range(1,2+1)})
            self.derived.topology.add_node(1004, ports={i: Port(i) for i in range(1,2+1)})

            ### write your code ###: WIREUP VIRTUAL SWITCHES (see Figure 2 in the project description)
            self.derived.topology.add_link(Location(1001,1),Location(1000,4)) #internal s1001[1] -- s1000[4]
	    self.derived.topology.add_link(Location(1001,2),Location(1002,1)) #internal s1001[2] -- s1002[1]
	    self.derived.topology.add_link(Location(1002,2),Location(1003,1)) #internal s1002[2] -- s1003[1]
	    self.derived.topology.add_link(Location(1003,2),Location(1004,1)) #internal s1003[2] -- s1004[1]	
            #......................
        except:
            self.derived.topology = Topology()
        super(split_gateway,self).set_network(network)
        print "--- Underlying Gateway Topology ------"
        print self.underlying.topology
        print "--- Derived Gateway Topology ------"
        print self.derived.topology
