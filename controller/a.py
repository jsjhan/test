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
from ryu import cfg
from ryu.lib import hub
import base64
import random
import time
import memcache
import collections
import json
import sys
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
CONF = cfg.CONF


def read_init_file():
    # read parameter from config file,use the default if it is not found
    '''Register an option schema.
    Registering an option schema makes any option value which is previously
    or subsequently parsed from the command line or config files available
    as an attribute of this object.

    register_opts:Register multiple option schemas at once
    register_opts(self, opts, group=None)
    for opt in opts:
            self.register_opt(opt, group, clear_cache=False)
    

    StrOpt:Option with String type
    :param name: the option's name


    usage: 
    read .conf file
    group as section [group]
    register group at init 
    CONF.group.parameter
    '''
    CONF.register_opts([cfg.StrOpt('CONTROLLER_NAME',default=None),
                        cfg.IntOpt('DST_PORT',default=6653)]
                        ,group='PARAMETER')



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



def build_OFP_payload(desc,msg_type,port_no=0,switch=None,dpid=None,data=None,packet=None,buffer_id=None):
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
        #self.switches = {}
        #self.flow_table = {}
        #self.check = {}
        #self.check['arp']={}
        self.client = memcache.Client([mem_server],debug=True,cache_cas=True)
        #self.switches_tcp = {}
        #self.internal_links = {}
        #self.graph = {}
        #self.ip_to_switch = {}
        read_init_file()
        if CONF.PARAMETER.CONTROLLER_NAME is None:
            print 'controller_name is not given'
            print 'exit'
            sys.exit(0)
        
    def set_managed_switches(self,port):
        data_str = self.client.get("port-to-dpid")
        if data_str is None:
            return
        else:
            port_to_dpid=json.loads(data_str)
        for item in port_to_dpid:
            if port == item[0]:
                myport = item[0]
                mydpid = item[1]
        if 'mydpid' not in locals():
            return
        for i in xrange(1,10):
            key = 'controller-%d-switches' % i
            while True:
                data_str = self.client.gets(key)
                if data_str:
                    data=json.loads(data_str)
                    if mydpid in data:
                        if i != int(MEM_KEY[-1]):
                            data.remove(mydpid)
                    else:
                        if i == int(MEM_KEY[-1]):
                            data.append(mydpid)
                    data_json = json.dumps(data)
                    if self.client.cas(key,data_json):
                        break
                else:
                    break

    def set_port_to_dpid(self,dpid,ip,port):
        while True:
            data_str = self.client.gets("port-to-dpid")
            if data_str is None:
                data=[]
                result=[]
            else:
                data=json.loads(data_str)
            data.append([ip,port,dpid])
            data_json = json.dumps(data)
            if self.client.cas("port-to-dpid",data_json):
                break

    def set_tcp_stat(self,cur_seq,cur_ack,dpid=None,pre_seq=0,pre_ack=0):
        #mem_switches = json.loads(self.client.get(MEM_KEY))
        key = CONF.PARAMETER.CONTROLLER_NAME
        if dpid:
            key = CONF.PARAMETER.CONTROLLER_NAME+'-switches'
        while True:
            data_str = self.client.gets(key)
            if data_str is None:
                data=[]
                result=[]
            else:
                data=json.loads(data_str)
            if dpid:
                switch = {dpid}
                key = MEM_KEY+'-switches'
                if data:
                    if dpid in data:
                        break
                data.append(dpid)
                #print data
                data_json = json.dumps(data)
            else:
                #print data
                '''for pair in data:
                    if pre_ack in pair:
                        data.remove(pair)
                    if pre_seq in pair:
                        data.remove(pair)'''
                return
                data.append([cur_seq,cur_ack])
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
            cur_seq = p.seq
            cur_ack = p.ack
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
                if ofproto_parser.header(pkt.protocols[-1]):
                    version, msg_type, msg_len, xid = ofproto_parser.header(pkt.protocols[-1])
                    payload_length = len(bytearray(pkt.protocols[-1]))
                    cur_seq = cur_seq+payload_length
                    #fake datapath
                    desc = ofproto_protocol.ProtocolDesc()
                    desc.set_version(version=version)
                    #print pkt 
                    if msg_type == desc.ofproto.OFPT_ERROR:
                        print 'error'
                        return
                    if msg_type == desc.ofproto.OFPT_PACKET_IN:
                        self.set_managed_switches(port=p.src_port)
                        #find datapath.id
                        #add seq number to match next packet
                        add_seq = len(bytearray(pkt.protocols[-1]))
                        content = desc.ofproto_parser.OFPPacketIn(desc).parser(desc, version, msg_type, msg_len, xid,pkt.protocols[-1])
                        desc_pkt = packet.Packet(content.data)
                        desc_pkt_eth = desc_pkt.get_protocol(ethernet.ethernet)

                        '''test code two port switch'''
                        packet_in_port = content.match['in_port']
                        buffer_id = content.buffer_id
                        #print buffer_id
                        #print type(buffer_id)
                        if int(packet_in_port) == 1:
                            re_pkt = build_tcp_packet(re_pkt,OPFMSG)
                            OFP_payload = build_OFP_payload(desc,SEND_PACKET_OUT,port_no=2,data=content.data)
                            re_pkt.add_protocol(OFP_payload)
                            re_pkt.serialize()
                            add_seq = len(bytearray(OFP_payload))
                            self.send_packet_out(datapath,in_port,re_pkt.data)                    
                        else:
                            re_pkt = build_tcp_packet(re_pkt,OPFMSG)
                            OFP_payload = build_OFP_payload(desc,SEND_PACKET_OUT,port_no=1,data=content.data)
                            re_pkt.add_protocol(OFP_payload)
                            re_pkt.serialize()
                            add_seq = len(bytearray(OFP_payload))
                            self.send_packet_out(datapath,in_port,re_pkt.data)                    
    
                        return

                        '''process arp packet'''
                        if desc_pkt.get_protocol(arp.arp):
                            print 'process arp'
                            desc_pkt_arp = desc_pkt.get_protocol(arp.arp)
                            packet_in_port = content.match['in_port']
                            

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
                            self.send_packet_out(datapath,in_port,re_pkt.data)
                            


                            msg_type = ARP_HIGH_PRIO
                            re_pkt = build_tcp_packet(re_pkt,OPFMSG,add_seq=add_seq)
                            OFP_payload = build_OFP_payload(desc,msg_type,port_no=packet_in_port,packet=desc_pkt)
                            re_pkt.add_protocol(OFP_payload)
                            re_pkt.serialize()
                            add_seq = len(bytearray(OFP_payload))
                            self.send_packet_out(datapath,in_port,re_pkt.data)

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


                            
                        if desc_pkt.get_protocol(ipv4.ipv4):
                            '''process ipv4 packet'''
                            desc_pkt_ip = desc_pkt.get_protocol(ipv4.ipv4)
                            packet_in_port = content.match['in_port']
                            src = str(desc_pkt_ip.src)
                            dst = str(desc_pkt_ip.dst)


                        return

                    '''receive feature reply and send port desc stats request'''
                    if msg_type == desc.ofproto.OFPT_FEATURES_REPLY:
                        reply = desc.ofproto_parser.OFPSwitchFeatures.parser(desc,version,msg_type,msg_len,xid,pkt.protocols[-1])
                        self.set_tcp_stat(cur_seq=cur_seq,cur_ack=cur_ack,dpid=reply.datapath_id)
                        self.set_port_to_dpid(dpid=reply.datapath_id,ip=ip.src,port=p.src_port)
                        self.set_managed_switches(port=p.src_port)
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
                        cur_ack = cur_ack+add_seq
                        self.set_tcp_stat(cur_seq=cur_seq,cur_ack=cur_ack,pre_seq=p.seq,pre_ack=p.ack)
                        re_pkt = build_tcp_packet(re_pkt,OPFMSG,add_seq=add_seq)
                        OFP_payload = build_OFP_payload(desc,desc.ofproto.OFPT_MULTIPART_REQUEST)
                        add_seq = len(bytearray(OFP_payload)) 
                        re_pkt.add_protocol(OFP_payload)
                        re_pkt.serialize()
                        self.send_packet_out(datapath,in_port,re_pkt.data)

                        cur_ack = cur_ack+add_seq
                        self.set_tcp_stat(cur_seq=cur_seq,cur_ack=cur_ack,pre_seq=p.seq,pre_ack=p.ack)
                        return
                    '''receive port desc reply'''
                    if msg_type == desc.ofproto.OFPT_MULTIPART_REPLY:
                        print 'OFPT_MULTIPART_REPLY'
                        port = desc.ofproto_parser.OFPMultipartReply.parser(desc,version,msg_type,msg_len,xid,pkt.protocols[-1])
                        self.set_tcp_stat(cur_seq=cur_seq,cur_ack=p.ack,pre_seq=p.seq,pre_ack=p.ack) 
                        #print port
                        return
                    '''receive echo request'''
                    if msg_type == desc.ofproto.OFPT_ECHO_REQUEST:
                        reply = desc.ofproto_parser.OFPEchoRequest.parser(desc,version,msg_type,msg_len,xid,pkt.protocols[-1])
                        #print 'echo request'
                        #print reply
                        #print p.seq,p.ack
                        re_pkt = build_tcp_packet(re_pkt,OPFMSG)
                        OFP_payload = build_OFP_payload(desc,msg_type)
                        re_pkt.add_protocol(OFP_payload)
                        re_pkt.serialize()
                        add_seq = len(bytearray(pkt.protocols[-1]))
                        self.send_packet_out(datapath,in_port,re_pkt.data)
                        cur_ack = cur_ack+add_seq
                        self.set_tcp_stat(cur_seq=cur_seq,cur_ack=cur_ack,pre_seq=p.seq,pre_ack=p.ack)
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
                        return

            if p.bits & 0b000001:
                print 'send fin'
                re_pkt = build_tcp_packet(pkt,TCP_REPLY)
                #print re_pkt
                re_pkt.serialize()
                self.send_packet_out(datapath,in_port,re_pkt.data)


