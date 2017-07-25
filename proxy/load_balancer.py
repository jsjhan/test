from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
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
from ryu.lib import hub
from ryu.lib import mac
from ryu import cfg
from ryu import utils
import sys
import base64
import random
import time

TCP_REPLY = 0
OPFMSG = 1
LOAD_BALANCE_GID = 6
#FAILOVER_GID = 1
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
    CONF.register_opts([cfg.StrOpt('SWITCH_PORT',default='eth1'),
                        cfg.IntOpt('FAILOVER_GID',default=1),
                        cfg.IntOpt('CARP_GID',default=2),
                        cfg.StrOpt('LOGICAL_IP',default='192.168.67.5'),
                        cfg.StrOpt('CONTROLLER_MAC',default='66:41:7c:bc:20:30')]
                        ,group='PARAMETER')
    
    CONF.register_opts([
                        cfg.IntOpt('EXPIRED_TIME',default=3),
                        cfg.IntOpt('ADVBASE',default=1),
                        cfg.IntOpt('VRID',default=1),
                        cfg.IntOpt('PRIORITY',default=0)]
                        ,group='CARP')    
def remove_table_flows(datapath,table_id):
    '''
        delete all flow entries in table_id 
    '''
    ofproto = datapath.ofproto
    empty_match = datapath.ofproto_parser.OFPMatch()
    instructions = []
    flow_mod = datapath.ofproto_parser.OFPFlowMod(
                                                datapath=datapath,
                                                table_id=table_id,
                                                command=ofproto.OFPFC_DELETE,
                                                out_port=ofproto.OFPP_ANY,
                                                out_group=ofproto.OFPG_ANY,
                                                match=empty_match,
                                                instructions=instructions)
    datapath.send_msg(flow_mod)


def send_group_out(datapath,group,data):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    actions = [parser.OFPActionGroup(group)]
    buffer_id = ofproto.OFP_NO_BUFFER
    out = parser.OFPPacketOut(datapath=datapath,buffer_id=buffer_id,in_port=ofproto.OFPP_CONTROLLER,
                                                  actions=actions, data=data)
    datapath.send_msg(out)

'''
def carp_handler(datapath):
    packet = build_carp_ad_packet()
    #print packet
    packet.serialize()
    while(1):
        print "RUNNING: ",RUNNING    
        if RUNNING:
            print "send carp packet"
            send_group_out(datapath=datapath,group=CONF.PARAMETER.CARP_GID,data=packet.data)
            hub.sleep(CONF.CARP.ADVBASE)
        else:
            print "carp not send packet"
            hub.sleep(3)
''' 

def add_flow(datapath, priority, match, actions, buffer_id=None,idle_timeout=0,hard_timeout=0,out_group=0):
    '''
    add openflow rule to specific switch by a given datapath
    '''
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
                                    out_group=out_group,
                                    instructions=inst)
    else:
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    idle_timeout=idle_timeout,hard_timeout=hard_timeout,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM,
                                    out_group=out_group,match=match, instructions=inst)
    datapath.send_msg(mod)


def build_arp_packet(switch=None,dpid=None,pkt=None,in_port=0):
    '''
    build a arp packet to reply anyone who request specific ip address' mac
    '''
    if pkt:
        arp_content = pkt.get_protocols(arp.arp)[0]
        for p in switch[dpid]:
            if in_port in p:
                hw_addr = p[2]
                break
        src_mac = CONF.PARAMETER.CONTROLLER_MAC
        dst_mac = arp_content.src_mac
        dst_ip  = arp_content.src_ip
        src_ip = arp_content.dst_ip
        eth_pkt = ethernet.ethernet(dst=dst_mac,src=src_mac,
                                    ethertype=ether_types.ETH_TYPE_ARP)
        arp_pkt = arp.arp(src_mac=src_mac,src_ip=src_ip,
                                dst_mac=dst_mac,dst_ip=dst_ip,opcode=2)
        '''
        class Packet
        An instance is used to either decode or encode a single packet.
        need to add protocol in order
        '''
        p = packet.Packet()
        p.add_protocol(eth_pkt)
        p.add_protocol(arp_pkt)
        return p
    else:
        src_mac = CONF.PARAMETER.CONTROLLER_MAC
        dst_mac = mac.BROADCAST_STR 
        dst_ip  = CONF.PARAMETER.LOGICAL_IP
        src_ip = CONF.PARAMETER.LOGICAL_IP
        eth_pkt = ethernet.ethernet(dst=dst_mac,src=src_mac,
                                    ethertype=ether_types.ETH_TYPE_ARP)
        arp_pkt = arp.arp(src_mac=src_mac,src_ip=src_ip,
                          dst_mac=src_mac,dst_ip=dst_ip,opcode=1)
        p = packet.Packet()
        p.add_protocol(eth_pkt)
        p.add_protocol(arp_pkt)
        return p

def vrrp_ipv4_src_mac_address(vrid):
    return vrrp.VRRP_IPV4_SRC_MAC_ADDRESS_FMT % vrid



def build_carp_ad_packet(src_mac):
    # 16 bit for ip layer identification length
    # getrandbits return long int 
    identification = int(random.getrandbits(16))
    #total 3 bit in flags
    #position 0    : reserved
    #position 1 : don't fragment
    #position 2 : more fragment
    flags = 0b010
    eth_pkt = ethernet.ethernet(dst=vrrp.VRRP_IPV4_DST_MAC_ADDRESS,
                                #src=vrrp_ipv4_src_mac_address(CONF.CARP.VRID),
                                src=src_mac,
                                ethertype=ether_types.ETH_TYPE_IP)
    ip_pkt = ipv4.ipv4( identification=identification,
                        flags=flags,
                        ttl=vrrp.VRRP_IPV4_TTL,
                        proto=in_proto.IPPROTO_VRRP,
                        dst=vrrp.VRRP_IPV4_DST_ADDRESS)
    carp_pkt = vrrp.vrrpv2.create(type_=vrrp.VRRP_TYPE_ADVERTISEMENT,vrid=CONF.CARP.VRID,
                                    priority=0,max_adver_int=1,ip_addresses=[CONF.PARAMETER.LOGICAL_IP])
    p = packet.Packet()
    p.add_protocol(eth_pkt)
    p.add_protocol(ip_pkt)
    p.add_protocol(carp_pkt)
    return p

class load_balancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(load_balancer, self).__init__(*args, **kwargs)
        self.RUNNING = 3
        self.not_sent_arp = 1
        self.switches = {}
        self.flow_table = {}
        read_init_file()

    def send_port_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    def send_group_desc_stats_request(self, datapath):
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPGroupDescStatsRequest(datapath, 0)
        datapath.send_msg(req)


    @set_ev_cls(ofp_event.EventOFPGroupDescStatsReply, MAIN_DISPATCHER)
    def group_desc_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        descs = []
        for stat in ev.msg.body:
            descs.append('length=%d type=%d group_id=%d '
                'buckets=%s' %
                 (stat.length, stat.type, stat.group_id,
                              stat.buckets))
        if len(descs)==0 :
            return
        #delete all group table    
        for stat in ev.msg.body:
            req = parser.OFPGroupMod(datapath, ofp.OFPGC_DELETE, 
                    group_id=stat.group_id)
            datapath.send_msg(req)



    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        self.ports = []
        datapath = ev.msg.datapath
        dpid = str(datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        buffer_id = ofproto.OFP_NO_BUFFER
        temp = []
        for p in ev.msg.body:
            if p.port_no != ofproto_v1_3.OFPP_LOCAL:
                self.ports.append([p.port_no, p.hw_addr])
                temp.append([p.name,p.port_no,p.hw_addr])
        self.switches[datapath.id] = temp
        print self.switches 
        #match = parser.OFPMatch(in_port=1)
        #priority = 1
        #group_id = 1
        #actions = [parser.OFPActionGroup(group_id)]
        #add_flow(datapath, priority, match, actions,out_group=1)
        self.send_group_mod(datapath)
        self.controller_to_switch(datapath)



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
        self.send_group_desc_stats_request(datapath)
        self.send_port_stats_request(datapath)
        remove_table_flows(datapath=datapath,table_id=0)
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
        priority = 1
        # debug message
        #
        # notify the user dedicated OpenFlow switch of load balancer
        # is connected
        print 'switch online'
        print 'hello'
        #add packet in rule
        #all unrecognized packet will be sent to controller
        add_flow(datapath, priority, match, actions)
        
        '''match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_dst='224.0.0.18'
                )
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        priority = 5
        add_flow(datapath, priority, match, actions)'''
        

    def send_packet_out(self,datapath,port,data):
        # make dedicated switch sending forged packets
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(port)]
        buffer_id = ofproto.OFP_NO_BUFFER
        out = parser.OFPPacketOut(datapath=datapath,buffer_id=buffer_id,in_port=ofproto.OFPP_CONTROLLER,
                                                  actions=actions, data=data)
        datapath.send_msg(out)


    def controller_to_switch(self, datapath):
        # add rule that wrapped controller to managed switches
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        controller_port=()
        for port in self.switches[datapath.id]:
            if port[0].find(CONF.PARAMETER.SWITCH_PORT) == 0:
                switch_port=port[1]
        for port in self.switches[datapath.id]:
            if port[0].find(CONF.PARAMETER.SWITCH_PORT) < 0:
                #controller_port = controller_port + (port[1],)
                actions = [ofp_parser.OFPActionOutput(switch_port)]
        #print controller_port
                match = ofp_parser.OFPMatch(in_port=port[1])
                add_flow(datapath, 2, match, actions)
        
        #add carp rule
        match = ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ip_proto=in_proto.IPPROTO_VRRP)
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                              ofp.OFPCML_NO_BUFFER)]
        add_flow(datapath, 3, match, actions)
        

    def send_group_mod(self, datapath):
        # add all available ports to fast fail-over group except 
        # the physical port to managed switches
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        max_len = 2000
        available_port = []
        buckets = []
        for port in self.switches[datapath.id]:
            if port[0].find(CONF.PARAMETER.SWITCH_PORT) < 0:
                available_port.append(port[1])
            else:
                self.switch_port_mac = port[2]
        print available_port

        if len(available_port) == 0:
            print 'no available port'
            return
        
        
        for port in available_port:
            print 'add port '+str(port)+' to group'
            actions = [ofp_parser.OFPActionOutput(port)]
            weight = 1
            #weight = 0
            watch_port = port
            watch_group = ofp.OFPG_ANY
            buckets.append(ofp_parser.OFPBucket(weight, watch_port, watch_group,
                   actions))
            #buckets.append(ofp_parser.OFPBucket(actions=actions))
        group_id = CONF.PARAMETER.FAILOVER_GID
        req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_ADD,
                                     ofp.OFPGT_SELECT, group_id, buckets)
        datapath.send_msg(req)


        buckets = []
        for port in available_port:
            actions = [ofp_parser.OFPActionOutput(port)]
            buckets.append(ofp_parser.OFPBucket(actions=actions))
        group_id = CONF.PARAMETER.CARP_GID
        req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_ADD,
                                     ofp.OFPGT_ALL, group_id, buckets)
        datapath.send_msg(req)
        
        
        # spawn a new thread for CARP
        hub.spawn(self.carp_handler,datapath=datapath,src_mac=self.switch_port_mac)


    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        # only debug message
        # used for the link if it is connected or not
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        if msg.reason == ofp.OFPPR_ADD:
            reason = 'ADD'
        elif msg.reason == ofp.OFPPR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPPR_MODIFY:
            reason = 'MODIFY'
        else:
            reason = 'unknown'
        print reason
        print msg.desc
        if (msg.desc.state & ofp.OFPPS_LINK_DOWN) > 0:
            print 'OFPPS_LINK_DOWN'
        elif (msg.desc.state & ofp.OFPPS_BLOCKED) > 0:
            print 'OFPPS_BLOCKED'
        elif (msg.desc.state & ofp.OFPPS_LIVE) > 0:
            print 'OFPPS_LIVE'
   
    def carp_handler(self,datapath,src_mac):
        carp_packet = build_carp_ad_packet(src_mac=src_mac)
        carp_packet.serialize()
    
        arp_packet = build_arp_packet()
        arp_packet.serialize()

        for port in self.switches[datapath.id]:
            if port[0].find(CONF.PARAMETER.SWITCH_PORT) == 0:
                switch_port=port[1]


        #waiting for packet if other machine is sending packet
        hub.sleep(CONF.CARP.ADVBASE*2)
        while(1):
            if self.RUNNING == 3:
                send_group_out(datapath=datapath,group=CONF.PARAMETER.CARP_GID,data=carp_packet.data)
                #hub.sleep(0.5)
                if self.not_sent_arp:
                    print 'switch to carp master'
                    self.send_packet_out(datapath,switch_port,arp_packet.data)
                    self.not_sent_arp = 0
                hub.sleep(CONF.CARP.ADVBASE)
            else:
                if self.not_sent_arp == 0:
                    print 'switch to carp slave'
                print "carp not send packet"
                self.RUNNING = self.RUNNING + 1
                self.not_sent_arp = 1
                hub.sleep(CONF.CARP.ADVBASE)


 
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            return
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            if pkt.get_protocols(icmp.icmp):
                print 'icmp packet'
                return
        if pkt.get_protocols(vrrp.vrrpv2):
            if in_port is CONF.PARAMETER.SWITCH_PORT:
                return
            else:
                eth_mac = eth.src
                #print int(mac.replace(':',''),16)
                #print type(self.switch_port_mac)
                #print self.switch_port_mac
                #print int(self.switch_port_mac.replace(':',''),16)
                if int(eth_mac.replace(':',''),16) < int(self.switch_port_mac.replace(':',''),16):
                    self.RUNNING = 0
                if int(eth_mac.replace(':',''),16) == int(self.switch_port_mac.replace(':',''),16):
                    print 'MAC address conflict'
                    print 'in_port='+str(in_port)
                    print pkt
            return

        # if the managed switches send arp request to logical controller
        # load balancer receive the packet and return the arp reply
        if pkt.get_protocols(arp.arp):
            p = pkt.get_protocols(arp.arp)[0]
            print p
            if p.src_ip == CONF.PARAMETER.LOGICAL_IP:
                #arp packet for carp
                #dont care
                return
            if p.dst_ip == CONF.PARAMETER.LOGICAL_IP:
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_ARP,
                    eth_src=eth.src,
                    in_port=in_port,
                    arp_op=arp.ARP_REQUEST,
                    arp_tpa=CONF.PARAMETER.LOGICAL_IP
                    )
                actions = [ parser.OFPActionSetField(eth_src=CONF.PARAMETER.CONTROLLER_MAC),
                        parser.OFPActionSetField(eth_dst=eth.src),
                        parser.OFPActionSetField(arp_sha=CONF.PARAMETER.CONTROLLER_MAC),
                        parser.OFPActionSetField(arp_tha=p.src_mac),
                        parser.OFPActionSetField(arp_spa=CONF.PARAMETER.LOGICAL_IP),
                        parser.OFPActionSetField(arp_tpa=p.src_ip),
                        parser.OFPActionSetField(arp_op=arp.ARP_REPLY),
                        parser.OFPActionOutput(ofproto.OFPP_IN_PORT,ofproto.OFPCML_NO_BUFFER)]
                add_flow(datapath=datapath, priority=10, match=match, actions=actions)
                re_pkt = build_arp_packet(self.switches,datapath.id,pkt,in_port)
            #print re_pkt
                re_pkt.serialize()
                self.send_packet_out(datapath,in_port,re_pkt.data)
                return
        print 'receive packet'
        print pkt
        print 'in_port= '+str(in_port)
        if pkt.get_protocols(ipv4.ipv4):
            #tcp_pkt = pkt.get_protocols(tcp.tcp)[0]
            ip_pkt = pkt.get_protocols(ipv4.ipv4)[0]
            match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    in_port=in_port,
                    #eth_src=(eth.src,'FF:FF:FF:FF:FF:FF'),
                    ipv4_src=('192.168.67.0','255.255.255.0')
                )
            actions = [parser.OFPActionGroup(CONF.PARAMETER.FAILOVER_GID)]
            add_flow(datapath, 3, match, actions,out_group=CONF.PARAMETER.FAILOVER_GID)
                
     
