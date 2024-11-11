"""*************************************************************************************
 *
 * Date			: 29-04-2022
 * Author 		: Shamal Weerasooriya
 *
 * Description	: SDN Based Firewall
 *
 *************************************************************************************"""

# we have blocked_ips (list) , we check if the packet has source or destination in blocked ips , if yes we drop it = event.hault = true

from pox.core import core

blocked_ips = []

def _handle_IP_PacketIn(event):
    # gets the packet
    tcpPacket = event.parsed.find('tcp')
    # returns, if packet is not tcp
    if tcpPacket is None:
        return
    # gets the source and destination ip
    srcIp = tcpPacket.srcip
    dstIp = tcpPacket.dstip

    # if the (source ip, dst ip) is blocked, drop the packet
    if (srcIp, dstIp) in blocked_ips:
        print("Dropping packet from %s to %s" % (srcIp, dstIp))
        event.halt = True

def block(srcIp, dstIp):
    blocked_ips.append((srcIp, dstIp))

def unblock(srcIp, dstIp):
    blocked_ips.remove((srcIp, dstIp))

#entry point for SDN-based Firewall, use POX controller framework

def launch(ips = ''):
    # add blocks from CLI
    blocked_ips.append((ip[0], ip[1]) for ip in ips.split(' '))

   # allow the user to block and unblock IP pairs interactively while the controller is running. 
    core.Interactive.variables['block'] = block
    core.Interactive.variables['unblock'] = unblock

    # add the event handler                     # listener for incoming packets
    core.openflow.addListenerByName("PacketIn", _handle_IP_PacketIn)
