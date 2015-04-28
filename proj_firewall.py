#Code references: Open source Pyretic libraries, www.csg.ethz.ch, and Mininet documentation
#Upload this script into the Mininet-VM directory ~/pyretic/pyretic/examples

from pyretic.lib.corelib import *
from pyretic.lib.std import *

def poke(W,P):
    p = union([match(srcip=s,dstip=d) for (s,d) in W])
    return if_(p,passthrough,P)

class fw0(DynamicPolicy):
    #a dynamic (stateful) firewall that opens holes but doesn't close them
    def __init__(self,W):
        super(fw0,self).__init__()
        self.W = W
        self.open_holes = []
        self.wp = union([match(srcip=s,dstip=d) for (s,d) in W])
        self.forward = poke(W,drop)
        self.refresh()

    def update_policy(self):
        """Update the policy based on current forward and query policies"""
        self.policy = self.forward + (self.wp >> self.query)

    def allow_reverse(self,p):
        if (str(p['dstip']),str(p['srcip'])) not in self.W: #open holes that need to open
            """Open reverse hole for ongoing traffic"""
            print "poking hole for %s,%s" % (p['dstip'],p['srcip'])
            self.forward = poke({(p['dstip'],p['srcip'])},self.forward)
            self.open_holes.append((str(p['dstip']),str(p['srcip'])))
            self.update_policy()

    def refresh_query(self):
        """(Re)set the query checking for allowed traffic"""
        self.query = packets(1,['dstip','srcip'])
        self.query.register_callback(self.allow_reverse)

    def refresh(self):
        """Refresh the policy"""
        self.refresh_query()
        self.update_policy()

def patch(p,P):
    return if_(p,drop,P)

class fw(DynamicPolicy):
    #A dynamic (stateful) firewall that closes holes that it opens
    def __init__(self,W):
        super(fw,self).__init__()
        self.query = count_packets(1,['srcip','dstip'])
        self.query.register_callback(self.check_reverse)
        self.rps = []
        for (s,d) in W: #check only reverse holes that need to be closed (not in default whitelist)
            if (d,s) not in W:
                self.rps.append(match(srcip=d,dstip=s))
        self.H = { rp : (0,0) for rp in self.rps }
        self.T = 3
        self.inner = fw0(W)
        self.update_policy()
    
    def update_policy(self):
        #Update policy based on current inner and query policies
        self.policy = self.inner + (union(self.rps) >> self.query)
    
    def check_reverse(self,stats):
        #Close unused holes
        for (p,cnt) in stats.items():
            if (str(p.map['srcip'].pattern), str(p.map['dstip'].pattern)) in self.inner.open_holes:
                (pcnt,missed) = self.H[p]
                if pcnt < cnt: missed = 0   
                else:          missed += 1
                if missed == self.T:
                    print "%d seconds w/o traffic, closing hole" % self.T,
                    print p
                    self.inner.forward = patch(p,self.inner.forward)
                    self.inner.open_holes.remove((str(p.map['srcip'].pattern), str(p.map['dstip'].pattern)))
                    self.inner.refresh()
                    self.H[p] = (0,0) #reset
                else:
                    self.H[p] = (cnt,missed)

