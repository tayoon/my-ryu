from operator import truediv
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp

# IPアドレス
H1_IP_ADDR = '10.0.0.1'
H2_IP_ADDR = '10.0.0.2'
H3_IP_ADDR = '10.0.0.3'

class ProposalSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProposalSwitch, self).__init__(*args, **kwargs)
        # MACアドレステーブルを初期化
        self.mac_to_port = {}

    # Packet-Inメッセージを受信する準備
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # print('***** switch_feature_handler *****')
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # SwitchのIPアドレス
        # self.logger.info(datapath.address[0])

        # Table-missフローエントリの追加
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Flow-Modメッセージ（追加）
    def add_flow(self, datapath, priority, match, actions):
        # print('##### add_flow #####')
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Flow Modメッセージの作成、送信
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # Flow-Modメッセージ（更新）
    def change_flow(self, datapath, priority, match, cookie, actions):
        # print('##### change_flow #####')
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Flow Modメッセージの作成、送信
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, cookie=cookie, command=ofproto.OFPFC_MODIFY, instructions=inst)
        datapath.send_msg(mod)

    # Packet-Inメッセージ
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # print('$$$$$ packet_in_handler $$$$$')
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # ホストのIPアドレスをリストに追加
        host_ip = list()
        host_ip.append(H1_IP_ADDR)
        host_ip.append(H2_IP_ADDR)

        # print(host_ip)

        # Datapath IDの取得（OpenFlowスイッチの識別）
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # 受信パケットの分析
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dst = eth_pkt.dst
        src = eth_pkt.src

        # self.logger.info(pkt)

        # test
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        # self.logger.info(ipv4_pkt)

        if ipv4_pkt == None:
            # print("+++++ gone +++++")
            # 受信ポートの番号を取得
            in_port = msg.match['in_port']

            # self.logger.info("packet in (Datapath ID)%s, (src)%s, (dst)%s, (received port)%s", dpid, src, dst, in_port)

            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port

            # if the destination mac address is already learned,
            # decide which port to output the packet, otherwise FLOOD.
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            # アクションリストの作成
            actions = [parser.OFPActionOutput(out_port)]

            # フローエントリの追加
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                self.add_flow(datapath, 1, match, actions)

            # Packet-Outの作成、送信
            out = parser.OFPPacketOut(datapath=datapath,
                                    buffer_id=ofproto.OFP_NO_BUFFER,
                                    in_port=in_port, actions=actions,
                                    data=msg.data)
            # to OFC
            datapath.send_msg(out)
        else:
            # IP addressの確認
            flag = self.ipaddress_check(pkt, host_ip)

            # IP addressの判定
            if flag == True:
                print('I know this IP address!!')
                # 受信ポートの番号を取得
                in_port = msg.match['in_port']

                self.logger.info("packet in (Datapath ID)%s, (src)%s, (dst)%s, (received port)%s", dpid, src, dst, in_port)

                # learn a mac address to avoid FLOOD next time.
                self.mac_to_port[dpid][src] = in_port

                # if the destination mac address is already learned,
                # decide which port to output the packet, otherwise FLOOD.
                if dst in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][dst]
                else:
                    out_port = ofproto.OFPP_FLOOD

                # アクションリストの作成
                actions = [parser.OFPActionOutput(out_port)]

                # フローエントリの追加
                if out_port != ofproto.OFPP_FLOOD:
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                    self.add_flow(datapath, 1, match, actions)

                # Packet-Outの作成、送信
                out = parser.OFPPacketOut(datapath=datapath,
                                        buffer_id=ofproto.OFP_NO_BUFFER,
                                        in_port=in_port, actions=actions,
                                        data=msg.data)
                # to OFC
                datapath.send_msg(out)

            else:
                print('I do not know this IP address...')

                ipv4_src = ipv4_pkt.src

                # 受信ポートの番号を取得
                in_port = msg.match['in_port']

                # test
                # match = parser.OFPMatch(eth_type=0x806, ipv4_src=ipv4_src)
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                
                # Drop処理
                actions = []
                self.add_flow(datapath, 10, match, actions)

                print('<<<<<<DROP PACKET>>>>>>')

    # IP addressの確認
    def ipaddress_check(self, pkt, host_ip):
        flag = True

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        # self.logger.info('ipv4 info = %s', ipv4_pkt)
        ipv4_src = ipv4_pkt.src
        
        for ip in host_ip:
            if ipv4_src == ip:
                flag = True
                # print("ooooo flag is True ooooo")
                self.logger.info("ooooo flag is True ooooo   --> %s", ipv4_src)
                break
            else:
                flag = False
                # print("xxxxx flag is False xxxxx")
                self.logger.info("xxxxx flag is False xxxxx   --> %s", ipv4_src)
            
        return flag
