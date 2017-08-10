from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_parser
from ryu.ofproto import ofproto_protocol
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from ryu.lib.packet import lldp
from ryu.lib.packet import icmp
from ryu.lib.packet import vrrp
from ryu.lib.packet import in_proto
from ryu.controller import handler
from ryu.lib.mac import haddr_to_bin
from ryu.lib import hub
import base64
import random
import time
import memcache
import collections
import json
compare = lambda x, y: collections.Counter(x) == collections.Counter(y)
memcached_pool = ['10.0.248.68','10.0.115.247']
local_ip = '192.168.67.5'
mem_server = '10.0.3.20:11211'
TCP_REPLY = 0
OPFMSG = 1
ADD_LLDP_RULE = 50
SEND_LLDP_PACKET = 51
SEND_PACKET_OUT = 52
ARP_DROP_PACKET = 53
ARP_HIGH_PRIO = 54
ARP_REPLY = 55
ARP_REMOVE = 56
ADD_LAYER2_RULE = 57
MEM_KEY='controller-1'
MEM_GRAPH_KEY='graph'
MEM_LINK_KEY='links'
MEM_CHECK_KEY='check'
MEM_IP_KEY='ip_switch'



def add_flow(datapath, priority, match, actions, buffer_id=None,idle_timeout=0,hard_timeout=0):
    dpid = str(datapath.id)
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
    if buffer_id:
        mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    idle_timeout=idle_timeout,hard_timeout=hard_timeout,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                                    instructions=inst)
    else:
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    idle_timeout=idle_timeout,hard_timeout=hard_timeout,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                                    match=match, instructions=inst)
    datapath.send_msg(mod)


def build_tcp_packet(pkt,ctl,add_seq=0):
    #ethernet proto
    eth = pkt.get_protocols(ethernet.ethernet)[0]

    #ip proto
    ip = pkt.get_protocols(ipv4.ipv4)[0]
    dst_ip = ip.src
    src_ip = ip.dst
    identification = random.randint(1, 5000)

    #tcp proto
    mytcp = pkt.get_protocols(tcp.tcp)[0]
    myseq = mytcp.ack
    myack = mytcp.seq
    option = mytcp.option

    #Syn bit
    if mytcp.bits & 0b000010 :
        bits = 0b010010
        myseq = random.getrandbits(32)
        myack += 1
        #mem_add_tcp_seq(str(myseq),str(myack+1))
        '''for i in range(0,len(option)):
            if option[i].kind == tcp.TCP_OPTION_KIND_TIMESTAMPS:
                my_ts_ecr = option[i].ts_val
                my_tc_val = (int(time.time()) & 0xffffffff)
                option[i] = tcp.TCPOptionTimestamps(ts_val=my_tc_val, ts_ecr=my_ts_ecr)'''
    #Fin bit
    if mytcp.bits & 0b000001 :
        bits = 0b010001 
        myack += 1
        '''for i in range(0,len(option)):
            if option[i].kind == tcp.TCP_OPTION_KIND_TIMESTAMPS:
                my_ts_ecr = option[i].ts_val
                my_tc_val = (int(time.time()) & 0xffffffff)
                option[i] = tcp.TCPOptionTimestamps(ts_val=my_tc_val, ts_ecr=my_ts_ecr)'''

    #Psh bit
    if mytcp.bits & 0b001000 :
        bits = 0b010000
        myack += len(pkt.protocols[-1])
        '''for i in range(0,len(option)):
            if option[i].kind == tcp.TCP_OPTION_KIND_TIMESTAMPS:
                my_ts_ecr = option[i].ts_val
                my_tc_val = (int(time.time()) & 0xffffffff)
                option[i] = tcp.TCPOptionTimestamps(ts_val=my_tc_val, ts_ecr=my_ts_ecr)'''

    #forged header
    if ctl:
        #forged openflow header
        #ethernet
        eth_pkt = eth

        #ip proto
        ip_pkt = ipv4.ipv4(version=4, header_length=5,
                        tos=0, total_length=0,
                        identification=ip.identification+1, flags=2,
                        offset=0, ttl=64,
                        proto=in_proto.IPPROTO_TCP, csum=0,
                        src=ip.src, dst=ip.dst)
        #tcp proto
        #psh ack bit
        bits = 0b011000
        tcp_pkt = tcp.tcp(src_port=mytcp.src_port, dst_port=mytcp.dst_port,
                    seq=mytcp.seq+add_seq, ack=mytcp.ack, offset=0,
                    bits=bits, window_size=2048,
                    csum=0, urgent=0, option=None)

    else:
        #forged normal header
        #ethernet proto
        dst_mac = eth.src
        src_mac = eth.dst
        eth_pkt = ethernet.ethernet(dst_mac,src_mac,ethertype=ether_types.ETH_TYPE_IP)

        #ip proto
        ip_pkt = ipv4.ipv4(version=4, header_length=5,
                        tos=0, total_length=0,
                        identification=identification, flags=2,
                        offset=0, ttl=64,
                        proto=in_proto.IPPROTO_TCP, csum=0,
                        src=src_ip, dst=dst_ip)

        #tcp proto
        tcp_pkt = tcp.tcp(src_port=mytcp.dst_port, dst_port=mytcp.src_port, 
                    seq=myseq, ack=myack, offset=0, 
                    bits=bits, window_size=2048, 
                    csum=0, urgent=0, option=None)

    p = packet.Packet()
    p.add_protocol(eth_pkt)
    p.add_protocol(ip_pkt)
    p.add_protocol(tcp_pkt)
    return p

def build_new_packet(switch):
    src_eth = switch['src_eth']
    dst_eth = switch['dst_eth']
    src_ip = switch['src_ip']
    dst_ip = switch['dst_ip']
    ip_id = switch['ip_id']
    seq = switch['seq']
    ack = switch['ack']
    src_port = switch['src_port']
    dst_port = switch['dst_port']

    #eth proto
    eth_pkt = ethernet.ethernet(src_eth,dst_eth,ethertype=ether_types.ETH_TYPE_IP)
    #ip proto
    ip_pkt = ipv4.ipv4(version=4, header_length=5,
                    tos=0, total_length=0,
                        identification=ip_id+1, flags=2,
                        offset=0, ttl=64,
                        proto=in_proto.IPPROTO_TCP, csum=0,
                        src=dst_ip, dst=src_ip)
    #tcp proto
    #psh ack bit
    bits = 0b011000
    tcp_pkt = tcp.tcp(src_port=dst_port, dst_port=src_port,
                    seq=ack, ack=seq, offset=0,
                    bits=bits, window_size=2048,
                    csum=0, urgent=0, option=None)
    p = packet.Packet()
    p.add_protocol(eth_pkt)
    p.add_protocol(ip_pkt)
    p.add_protocol(tcp_pkt)
    return p



def build_OFP_payload(desc,msg_type,port_no=0,switch=None,dpid=None,data=None,packet=None):
    #openflow hello
    ofproto = desc.ofproto
    parser = desc.ofproto_parser
    if msg_type == ofproto.OFPT_HELLO:
        #print 'ofp hello'
        payload = parser.OFPHello(desc)

    #openflow echo
    if msg_type == ofproto.OFPT_ECHO_REQUEST:
        #print 'ofp echo reply'
        payload = parser.OFPEchoReply(desc,data='hello')

    #openflow flow mod
    if msg_type == ofproto.OFPT_FLOW_MOD:
        #print 'ofp flow mod'
        match = parser.OFPMatch()
        #openflow1.3
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
        #openflow1.0
        #actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        
        #openflow1.3
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        payload = parser.OFPFlowMod(desc,priority=0,match=match,instructions=inst)

        #openflow1.0
        #payload = parser.OFPFlowMod(desc,priority=0,match=match,actions=actions)




    if msg_type == ADD_LLDP_RULE:
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_LLDP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        payload = parser.OFPFlowMod(desc,priority=65535,match=match,instructions=inst)
    #openflow feature request
    if msg_type == ofproto.OFPT_FEATURES_REQUEST:
        #print 'ofp feature request'
        payload = parser.OFPFeaturesRequest(desc)
    if msg_type == ofproto.OFPT_MULTIPART_REQUEST:
        #print 'OFPT_MULTIPART_REQUEST'
        payload = parser.OFPPortDescStatsRequest(desc)

    if msg_type == SEND_LLDP_PACKET:
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_LLDP, src=switch['port'][port_no][0], dst=lldp.LLDP_MAC_NEAREST_BRIDGE))
        tlv_chassis_id = lldp.ChassisID(subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED, chassis_id=dpid)
        tlv_port_id = lldp.PortID(subtype=lldp.PortID.SUB_LOCALLY_ASSIGNED, port_id=str(port_no))
        tlv_ttl = lldp.TTL(ttl=10)
        tlv_end = lldp.End()
        tlvs = (tlv_chassis_id, tlv_port_id, tlv_ttl, tlv_end)
        pkt.add_protocol(lldp.lldp(tlvs))
        pkt.serialize()
        data = pkt.data
        actions=[parser.OFPActionOutput(port=port_no)]
        payload = parser.OFPPacketOut(datapath=desc, buffer_id=ofproto.OFP_NO_BUFFER, 
                     in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)

    if msg_type == SEND_PACKET_OUT:
        actions = [parser.OFPActionOutput(port=port_no)]
        payload = parser.OFPPacketOut(datapath=desc, buffer_id=ofproto.OFP_NO_BUFFER,
                     in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
    
    if msg_type == ARP_DROP_PACKET:
        eth = packet.get_protocols(ethernet.ethernet)[0]
        pkt_arp = packet.get_protocols(arp.arp)[0]
        match = parser.OFPMatch(eth_src=eth.src,eth_type=ether_types.ETH_TYPE_ARP,arp_op=arp.ARP_REQUEST,arp_tpa=pkt_arp.dst_ip)
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        payload = parser.OFPFlowMod(desc,priority=1,match=match,instructions=inst)
    if msg_type == ARP_HIGH_PRIO:
        eth = packet.get_protocols(ethernet.ethernet)[0]
        pkt_arp = packet.get_protocols(arp.arp)[0]
        match = parser.OFPMatch(eth_src=eth.src,eth_type=ether_types.ETH_TYPE_ARP,arp_op=arp.ARP_REQUEST,arp_tpa=pkt_arp.dst_ip,in_port=port_no)

        actions = [parser.OFPActionOutput(ofproto.OFPP_ALL,ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        payload = parser.OFPFlowMod(desc,priority=4,match=match,instructions=inst)
        
    if msg_type == ARP_REPLY:
        eth = packet.get_protocols(ethernet.ethernet)[0]
        pkt_arp = packet.get_protocols(arp.arp)[0]
        match = parser.OFPMatch(eth_dst=eth.src,eth_type=ether_types.ETH_TYPE_ARP,arp_op=arp.ARP_REPLY)

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER),
                    parser.OFPActionOutput(port_no,ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        payload = parser.OFPFlowMod(desc,priority=3,match=match,instructions=inst)

    if msg_type == ARP_REMOVE:
        eth = packet.get_protocols(ethernet.ethernet)[0]
        pkt_arp = packet.get_protocols(arp.arp)[0]
        match = parser.OFPMatch(eth_dst=eth.src,eth_type=ether_types.ETH_TYPE_ARP,arp_op=arp.ARP_REPLY)
        actions = []
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        payload = parser.OFPFlowMod(desc,command=ofproto.OFPFC_DELETE,match=match)

    if msg_type == ADD_LAYER2_RULE:
        eth = packet.get_protocols(ethernet.ethernet)[0]
        pkt_arp = packet.get_protocols(arp.arp)[0]
        match = parser.OFPMatch(eth_dst=eth.src,eth_src=eth.dst)

        actions = [parser.OFPActionOutput(port_no,ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        payload = parser.OFPFlowMod(desc,priority=3,match=match,instructions=inst)



    payload.serialize()
    return payload.buf

    
    

class a(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,ofproto_v1_3.OFP_VERSION]
    #OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(a, self).__init__(*args, **kwargs)
        self.switches = {}
        self.flow_table = {}
        self.check = {}
        self.check['arp']={}
        self.client = memcache.Client([mem_server],debug=True,cache_cas=True)
        self.switches_tcp = {}
        self.tcp_stat = {}
        self.internal_links = {}
        self.graph = {}
        self.ip_to_switch = {}
        self.test_arp = {}
    def set_tcp_stat(self,cur_seq,cur_ack,add_seq=None,dpid=None):
        #mem_switches = json.loads(self.client.get(MEM_KEY))
        if dpid:
            key = MEM_KEY+'-switches'
        else:
            key = MEM_KEY
        while True:
            data_str = self.client.gets(key)
            if data_str is None:
                data=[]
                result=[]
            else:
                data=json.loads(data_str)
                for switch in self.switches:
                    if cur_seq == data[switch]['seq']:
                        data[switch]['seq'] += add_seq
            if dpid:
                switch = {dpid}
                key = MEM_KEY+'-switches'
                data.append(dpid)
                #print data
                data_json = json.dumps(data)
            
            if self.client.cas(key,data_json):
                break
        



    def send_port_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    def mem_alive_handler(self):
        #self.client.delete(MEM_KEY+'_alive')
        while(1):
            #MEM_KEY
            time = None
            stats= self.client.get_stats()
            for item in stats[0]:
                if 'time' in item:
                    time = item['time']
            if time:
                self.client.set(MEM_KEY+'-alive',time)
            hub.sleep(1)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        self.ports = []
        datapath = ev.msg.datapath
        dpid = str(datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        buffer_id = ofproto.OFP_NO_BUFFER
        temp = [datapath]
        for p in ev.msg.body:
            if p.port_no != ofproto_v1_3.OFPP_LOCAL:
                self.ports.append([p.port_no, p.hw_addr])
                temp.append([p.port_no,p.hw_addr])
        hub.spawn(self.mem_alive_handler)
            
        #self.switches[datapath.id] = temp
        #self.mac = self.switches[datapath.id][1][1]
        
        '''
        #add carp rule
        actions = []
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ip_proto=in_proto.IPPROTO_VRRP)
        for p in self.ports:
            actions.append(parser.OFPActionOutput(p[0],
                                          ofproto.OFPCML_NO_BUFFER))
        priority = 1
        add_flow(datapath, priority, match, actions)
        '''
        
        

    @set_ev_cls(ofp_event.EventOFPErrorMsg,MAIN_DISPATCHER)
    def error_msg_handler(self, ev):
        msg = ev.msg
        self.logger.info('OFPErrorMsg received: type=0x%02x code=0x%02x message=%s',msg.type, msg.code, utils.hex_array(msg.data))



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = str(datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.send_port_stats_request(datapath)
        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        #print datapath.ofproto

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        priority = 0
        add_flow(datapath, priority, match, actions)
        

        #add carp rule
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ip_proto=in_proto.IPPROTO_VRRP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_ALL,
                                          ofproto.OFPCML_NO_BUFFER)] 
        priority = 1
        add_flow(datapath, priority, match, actions)

        
        print 'switch online'


    def send_packet_out(self,datapath,port,data):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(port)]
        buffer_id = ofproto.OFP_NO_BUFFER
        out = parser.OFPPacketOut(datapath=datapath,buffer_id=buffer_id,in_port=ofproto.OFPP_CONTROLLER,
                                                  actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        #print msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            return
        if pkt.get_protocols(vrrp.vrrp):
            print 'receive vrrp packet'
            print pkt
            return
        if pkt.get_protocols(ipv4.ipv4)[0].dst != local_ip:
            return

        if pkt.get_protocols(tcp.tcp):
            p = pkt.get_protocols(tcp.tcp)[0]
            ip = pkt.get_protocols(ipv4.ipv4)[0]
            #print pkt
            if p.bits & 0b000010:
                #receive SYN packet
                re_pkt = build_tcp_packet(pkt,TCP_REPLY)
                re_pkt.serialize()
                self.send_packet_out(datapath,in_port,re_pkt.data)
                #self.set_tcp_stat(p.seq,add_seq)

            if p.bits & 0b001000:
                #receive PSH packet
                re_pkt = build_tcp_packet(pkt,TCP_REPLY)
                re_pkt.serialize()
                self.send_packet_out(datapath,in_port,re_pkt.data)
                #self.set_tcp_stat(p.seq)
                '''for switch in self.switches:
                    if p.seq == self.switches[switch]['seq']:
                        #print '======================== match =========================='
                        mem_switches = json.loads(self.client.get(MEM_KEY))
                        self.switches[switch]['ack'] = p.ack
                        mem_switches[switch]['ack'] = p.ack
                        self.client.set(MEM_KEY,json.dumps(mem_switches))
                        print mem_switches'''
                if ofproto_parser.header(pkt.protocols[-1]):
                    version, msg_type, msg_len, xid = ofproto_parser.header(pkt.protocols[-1])
                    #print 'packet content',version, msg_type, msg_len, xid
                    #print 'receive msg type:  ',msg_type
                    #fake datapath
                    desc = ofproto_protocol.ProtocolDesc()
                    desc.set_version(version=version)
                    
                    #print 'payload len',len(bytearray(pkt.protocols[-1]))
                    '''for switch in self.switches:
                        if 'src_port' in self.switches[switch]:
                            if p.src_port == self.switches[switch]['src_port']:
                                if p.seq < self.switches[switch]['seq']:
                                    print 'seq less than cur seq'
                    for switch in self.switches:
                        if 'src_port' not in self.switches[switch]:
                            continue
                        if p.src_port == self.switches[switch]['src_port']:
                            if p.seq == self.switches[switch]['seq']:
                                self.switches[switch]['ack'] += len(bytearray(pkt.protocols[-1]))  
                                mem_switches = json.loads(self.client.get(MEM_KEY))
                                mem_switches[switch]['ack'] += len(bytearray(pkt.protocols[-1]))
                                self.client.set(MEM_KEY,json.dumps(mem_switches))'''
                    if msg_type == desc.ofproto.OFPT_ERROR:
                        print 'error'
                        return
                    #self.client.cas(str(p.seq),p.ack)
                    if msg_type == desc.ofproto.OFPT_PACKET_IN:
                        #print 'openflow packet in'
                        #print pkt
                        #find datapath.id
                        sw_dpid = None
                        for switch in self.switches:
                            if p.seq == self.switches[switch]['seq']:
                                sw_dpid = switch
                            '''if p.src_port == self.switches[switch]['src_port']:
                                sw_dpid = switch'''
                        #add seq number to match next packet
                        add_seq = len(bytearray(pkt.protocols[-1]))
                        #self.set_tcp_stat(p.seq,add_seq)
                        #print self.switches

                        content = desc.ofproto_parser.OFPPacketIn(desc).parser(desc, version, msg_type, msg_len, xid,pkt.protocols[-1])
                        desc_pkt = packet.Packet(content.data)
                        #print "packet,",desc_pkt

                        desc_pkt_eth = desc_pkt.get_protocol(ethernet.ethernet)

                        '''receive lldp packet'''
                        '''if desc_pkt.get_protocol(lldp.lldp):
                            if sw_dpid == None:
                                for switch in self.switches:
                                    if 'src_port' in self.switches[switch] and p.src_port == self.switches[switch]['src_port']:
                                        sw_dpid = switch
                                    if p.seq == self.switches[switch]['seq']:
                                        sw_dpid = switch
                            desc_pkt_lldp = desc_pkt.get_protocol(lldp.lldp)
                            packet_in_port = content.match['in_port']
                            for tlvs in desc_pkt_lldp.tlvs:
                                if hasattr(tlvs,'chassis_id'):
                                    chassis_id = str(tlvs.chassis_id)
                                if hasattr(tlvs,'port_id'):
                                    port_id = int(tlvs.port_id)
                            if sw_dpid not in self.internal_links:  
                                self.internal_links.setdefault(sw_dpid,{})
                                self.internal_links[sw_dpid].setdefault(chassis_id,port_id)
                            else:
                                self.internal_links[sw_dpid].setdefault(chassis_id,port_id)
                            #self.graph.setdefault(sw_dpid,{})
                            #self.graph[sw_dpid].setdefault(chassis_id,1)
                            mem_graph = self.client.get(MEM_GRAPH_KEY)
                            if mem_graph is not None:
                                mem_graph = json.loads(mem_graph)
                            else:
                                mem_graph = {}
                            mem_graph.setdefault(sw_dpid,{})
                            mem_graph[sw_dpid].setdefault(chassis_id,1)
                            self.graph = mem_graph
                            self.client.set(MEM_GRAPH_KEY,json.dumps(mem_graph))

                            mem_links = self.client.get(MEM_LINK_KEY)
                            if mem_links is not None:
                                mem_links = json.loads(mem_links)
                            else:
                                mem_links = {}
                            mem_links.setdefault(sw_dpid,{})
                            mem_links[sw_dpid].setdefault(chassis_id,port_id)
                            self.internal_links = mem_links
                            self.client.set(MEM_LINK_KEY,json.dumps(mem_links))


                            msg_type = SEND_LLDP_PACKET
                            if chassis_id not in self.internal_links or sw_dpid not in self.internal_links[chassis_id]:
                                if 'port' not in self.switches[sw_dpid]:
                                    return
                                re_pkt = build_tcp_packet(re_pkt,OPFMSG)
                                OFP_payload = build_OFP_payload(desc,msg_type,port_no=packet_in_port,
                                                                switch=self.switches[sw_dpid],dpid=sw_dpid)
                                re_pkt.add_protocol(OFP_payload)
                                re_pkt.serialize()
                                add_seq = len(bytearray(OFP_payload))
                                #print add_seq
                                self.send_packet_out(datapath,in_port,re_pkt.data)
                                self.set_tcp_stat(p.seq,add_seq)
                            print self.graph
                            #print self.internal_links
                            return'''
                        '''process arp packet'''
                        if desc_pkt.get_protocol(arp.arp):
                            print 'process arp'
                            desc_pkt_arp = desc_pkt.get_protocol(arp.arp)
                            packet_in_port = content.match['in_port']
                            

                            for switch in self.switches:
                                if p.seq == self.switches[switch]['seq']:
                                    sw_dpid = switch




                            msg_type = ARP_DROP_PACKET
                            re_pkt = build_tcp_packet(re_pkt,OPFMSG)
                            OFP_payload = build_OFP_payload(desc,msg_type,port_no=packet_in_port,packet=desc_pkt)
                            re_pkt.add_protocol(OFP_payload)
                            re_pkt.serialize()
                            add_seq = len(bytearray(OFP_payload))
                            #print add_seq
                            self.send_packet_out(datapath,in_port,re_pkt.data)
                            #self.set_tcp_stat(p.seq,add_seq)
                            
                            msg_type = ARP_REPLY
                            re_pkt = build_tcp_packet(re_pkt,OPFMSG,add_seq=add_seq)
                            OFP_payload = build_OFP_payload(desc,msg_type,port_no=packet_in_port,packet=desc_pkt)
                            re_pkt.add_protocol(OFP_payload)
                            re_pkt.serialize()
                            add_seq = len(bytearray(OFP_payload))
                            #print add_seq
                            self.send_packet_out(datapath,in_port,re_pkt.data)
                            #self.set_tcp_stat(p.seq,add_seq)
                            self.test_arp[sw_dpid] = packet_in_port
                            


                            msg_type = ARP_HIGH_PRIO
                            re_pkt = build_tcp_packet(re_pkt,OPFMSG,add_seq=add_seq)
                            OFP_payload = build_OFP_payload(desc,msg_type,port_no=packet_in_port,packet=desc_pkt)
                            re_pkt.add_protocol(OFP_payload)
                            re_pkt.serialize()
                            add_seq = len(bytearray(OFP_payload))
                            #print add_seq
                            self.send_packet_out(datapath,in_port,re_pkt.data)
                            #self.set_tcp_stat(p.seq,add_seq)

                            if desc_pkt_arp.opcode == arp.ARP_REPLY:
                                msg_type = ARP_REMOVE
                                re_pkt = build_tcp_packet(re_pkt,OPFMSG,add_seq=add_seq)
                                OFP_payload = build_OFP_payload(desc,msg_type,port_no=packet_in_port,packet=desc_pkt)
                                re_pkt.add_protocol(OFP_payload)
                                re_pkt.serialize()
                                add_seq = len(bytearray(OFP_payload))
                                #print add_seq
                                self.send_packet_out(datapath,in_port,re_pkt.data)
                                #self.set_tcp_stat(p.seq,add_seq)
                        
                                msg_type = ADD_LAYER2_RULE
                                re_pkt = build_tcp_packet(re_pkt,OPFMSG,add_seq=add_seq)
                                OFP_payload = build_OFP_payload(desc,msg_type,port_no=packet_in_port,packet=desc_pkt)
                                re_pkt.add_protocol(OFP_payload)
                                re_pkt.serialize()
                                add_seq = len(bytearray(OFP_payload))
                                #print add_seq
                                self.send_packet_out(datapath,in_port,re_pkt.data)
                                #self.set_tcp_stat(p.seq,add_seq)


                            
                            '''old'''
                            '''desc_pkt_arp = desc_pkt.get_protocol(arp.arp)
                            packet_in_port = content.match['in_port']
                            msg_type = SEND_PACKET_OUT
                            mem_check = self.client.get(MEM_CHECK_KEY)
                            flag = 0
                            if mem_check is None:
                                mem_ip = self.client.get(MEM_LINK_KEY)
                                if mem_ip is not None:
                                    mem_ip = json.loads(mem_ip)
                                else:
                                    mem_ip = {}
                                mem_check = {}
                                mem_check.setdefault('arp',{})
                                mem_ip.setdefault(desc_pkt_arp.src_ip,[sw_dpid,packet_in_port])
                                self.client.set(MEM_IP_KEY,json.dumps(mem_ip))
                            else:
                                mem_check = json.loads(mem_check)
                                for a in mem_check['arp']:                               
                                    if desc_pkt_arp.src_ip  == mem_check['arp'][a][-1]:
                                        flag =1
                                if flag == 0:
                                    self.ip_to_switch[desc_pkt_arp.src_ip] = [sw_dpid,packet_in_port]
                                    mem_ip = self.client.get(MEM_IP_KEY)
                                    if mem_ip is not None:
                                        mem_ip = json.loads(mem_ip)
                                    else:
                                        mem_ip = {}
                                    mem_ip.setdefault(desc_pkt_arp.src_ip,[sw_dpid,packet_in_port])
                                    self.client.set(MEM_IP_KEY,json.dumps(mem_ip))
    
                                

                            if sw_dpid not in mem_check['arp']:
                                mem_check['arp'][sw_dpid] = [desc_pkt_arp.dst_ip,desc_pkt_arp.src_mac,desc_pkt_arp.src_ip]
                            else:
                                for a in mem_check['arp'][sw_dpid]:
                                    if a == [desc_pkt_arp.dst_ip,desc_pkt_arp.src_mac,desc_pkt_arp.src_ip]:
                                        return
                                mem_check['arp'][sw_dpid] =[desc_pkt_arp.dst_ip,desc_pkt_arp.src_mac,desc_pkt_arp.src_ip]
                            self.client.set(MEM_CHECK_KEY,json.dumps(mem_check))
                            add_seq = 0
                            for port in self.switches[sw_dpid]['port']:
                                if port == packet_in_port:
                                    continue
                                re_pkt = build_tcp_packet(re_pkt,OPFMSG,add_seq=add_seq)
                                OFP_payload = build_OFP_payload(desc,msg_type,port_no=port,
                                                                data=content.data)
                                re_pkt.add_protocol(OFP_payload)
                                re_pkt.serialize()
                                add_seq = len(bytearray(OFP_payload))
                                self.send_packet_out(datapath,in_port,re_pkt.data)
                                self.set_tcp_stat(p.seq,add_seq)
                            return'''
                        if desc_pkt.get_protocol(ipv4.ipv4):
                            '''process ipv4 packet'''
                            desc_pkt_ip = desc_pkt.get_protocol(ipv4.ipv4)
                            packet_in_port = content.match['in_port']
                            src = str(desc_pkt_ip.src)
                            dst = str(desc_pkt_ip.dst)


                        return

                    '''receive feature reply and send port desc stats request'''
                    '''if msg_type == desc.ofproto.OFPT_FEATURES_REPLY:
                        dpid = str(desc.ofproto_parser.OFPSwitchFeatures(desc).parser(desc,version,msg_type,msg_len,xid,pkt.protocols[-1]).datapath_id)
                        re_pkt = build_tcp_packet(re_pkt,OPFMSG)
                        OFP_payload = build_OFP_payload(desc,desc.ofproto.OFPT_MULTIPART_REQUEST)
                        re_pkt.add_protocol(OFP_payload)
                        #print 'send openflow port desc stats request'
                        add_seq = len(bytearray(OFP_payload))
                        re_pkt.serialize()
                        self.send_packet_out(datapath,in_port,re_pkt.data)
                        return'''
                    if msg_type == desc.ofproto.OFPT_FEATURES_REPLY:
                        #print 'receive FEATURES_REPLY'
                        reply = desc.ofproto_parser.OFPSwitchFeatures.parser(desc,version,msg_type,msg_len,xid,pkt.protocols[-1])
                        print reply.datapath_id
                        self.set_tcp_stat(cur_seq=p.seq,cur_ack=p.ack,dpid=reply.datapath_id)
                        re_pkt = build_tcp_packet(re_pkt,OPFMSG)
                        
                        desc = ofproto_protocol.ProtocolDesc()
                        desc.set_version(version=version)
                        OFP_payload = build_OFP_payload(desc,desc.ofproto.OFPT_FLOW_MOD)
                        re_pkt.add_protocol(OFP_payload)
                        #add PACKETIN event to controller
                        re_pkt.serialize()
                        #print 'add packet in rule'       
                        add_seq = len(bytearray(OFP_payload))
                        self.send_packet_out(datapath,in_port,re_pkt.data)
                       
                        add_seq = len(bytearray(OFP_payload)) 
                        re_pkt = build_tcp_packet(re_pkt,OPFMSG,add_seq=add_seq)
                        OFP_payload = build_OFP_payload(desc,desc.ofproto.OFPT_MULTIPART_REQUEST)
                        re_pkt.add_protocol(OFP_payload)
                        re_pkt.serialize()
                        self.send_packet_out(datapath,in_port,re_pkt.data)
                        return
                    '''receive port desc reply'''
                    if msg_type == desc.ofproto.OFPT_MULTIPART_REPLY:
                        print 'OFPT_MULTIPART_REPLY'
                        port = desc.ofproto_parser.OFPMultipartReply.parser(desc,version,msg_type,msg_len,xid,pkt.protocols[-1])
                        #print port
                        return
                    '''receive echo request'''
                    if msg_type == desc.ofproto.OFPT_ECHO_REQUEST:
                        reply = desc.ofproto_parser.OFPEchoRequest.parser(desc,version,msg_type,msg_len,xid,pkt.protocols[-1])
                        #print 'echo request'
                        #print reply
                        re_pkt = build_tcp_packet(re_pkt,OPFMSG)
                        OFP_payload = build_OFP_payload(desc,msg_type)
                        re_pkt.add_protocol(OFP_payload)
                        re_pkt.serialize()
                        add_seq = len(bytearray(pkt.protocols[-1]))
                        self.send_packet_out(datapath,in_port,re_pkt.data)
                        #self.set_tcp_stat(cur_seq=p.seq,add_seq)
                        return
                    if msg_type == desc.ofproto.OFPT_HELLO:
                        re_pkt = build_tcp_packet(re_pkt,OPFMSG)
                        OFP_payload = build_OFP_payload(desc,msg_type)
                        re_pkt.add_protocol(OFP_payload)
                        '''send OFP HELLO to switch'''
                        re_pkt.serialize()
                        add_seq = len(bytearray(OFP_payload))
                        self.send_packet_out(datapath,in_port,re_pkt.data)
                        re_pkt = build_tcp_packet(re_pkt,OPFMSG,add_seq=add_seq)
                        OFP_payload = build_OFP_payload(desc,desc.ofproto.OFPT_FEATURES_REQUEST)
                        re_pkt.add_protocol(OFP_payload)
                        re_pkt.serialize()
                        add_seq = len(bytearray(OFP_payload))
                        self.send_packet_out(datapath,in_port,re_pkt.data)
                    #test openflow addflow
                    '''if msg_type == desc.ofproto.OFPT_HELLO:
                        re_pkt = build_tcp_packet(re_pkt,OPFMSG,add_seq=add_seq)
                        msg_type = desc.ofproto.OFPT_FLOW_MOD
                        desc = ofproto_protocol.ProtocolDesc()
                        desc.set_version(version=version)
                        OFP_payload = build_OFP_payload(desc,msg_type)
                        re_pkt.add_protocol(OFP_payload)
                        #add PACKETIN event to controller
                        re_pkt.serialize()
                        print 'add packet in rule'       
                        add_seq = len(bytearray(OFP_payload))
                        self.send_packet_out(datapath,in_port,re_pkt.data)

                        #add lldp rule
                        print 'add lldp rule'
                        re_pkt = build_tcp_packet(re_pkt,OPFMSG,add_seq=add_seq)
                        msg_type = ADD_LLDP_RULE
                        desc = ofproto_protocol.ProtocolDesc()
                        desc.set_version(version=version)
                        OFP_payload = build_OFP_payload(desc,msg_type)
                        re_pkt.add_protocol(OFP_payload)
                        re_pkt.serialize()
                        self.send_packet_out(datapath,in_port,re_pkt.data)


                        #test openflow feature request'''
                    '''if msg_type == desc.ofproto.OFPT_HELLO:
                            re_pkt = build_tcp_packet(re_pkt,OPFMSG,add_seq=add_seq)
                            msg_type = desc.ofproto.OFPT_FEATURES_REQUEST
                            desc = ofproto_protocol.ProtocolDesc()
                            desc.set_version(version=version)
                            OFP_payload = build_OFP_payload(desc,msg_type)
                            re_pkt.add_protocol(OFP_payload)
                            print 'send openflow feature request'
                            print re_pkt
                            re_pkt.serialize()
                            #print 'sent OFP header'
                            version, msg_type, msg_len, xid = ofproto_parser.header(bytearray(OFP_payload))
                            #print version, msg_type, msg_len, xid
                            self.send_packet_out(datapath,port[0],re_pkt.data)'''

                        
                    

            if p.bits & 0b000001:
                print 'send fin'
                re_pkt = build_tcp_packet(pkt,TCP_REPLY)
                #print re_pkt
                re_pkt.serialize()
                self.send_packet_out(datapath,in_port,re_pkt.data)


