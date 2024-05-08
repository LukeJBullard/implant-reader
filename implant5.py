from pylibpcap.pcap import Sniff
import subprocess, os
import keyboard
import time
from pylibpcap.pcap import rpcap
from utf12 import encode, decode

#set interface name here
interface=""

byte_sequence = [0x49,0x44,0x41,0x54]
target_bytes = bytes(byte_sequence)

class WifiChannel:
    def __init__(self, channel, control, center, bandwitdh):
        self.channel=channel
        self.control=control
        self.center=center
        self.bandwidth=bandwitdh
        self.out_pcap=0

wifichannels=list()
wifichannels.append(WifiChannel(1,  2412, 2412, 20))
wifichannels.append(WifiChannel(2,  2417, 2417, 20))
wifichannels.append(WifiChannel(3,  2422, 2422, 20))
wifichannels.append(WifiChannel(4,  2427, 2427, 20))
wifichannels.append(WifiChannel(5,  2432, 2432, 20))
wifichannels.append(WifiChannel(6,  2437, 2437, 20))
wifichannels.append(WifiChannel(7,  2442, 2442, 20))
wifichannels.append(WifiChannel(8,  2447, 2447, 20))
wifichannels.append(WifiChannel(9,  2452, 2452, 20))
wifichannels.append(WifiChannel(10, 2457, 2457, 20))
wifichannels.append(WifiChannel(11, 2462, 2462, 20))
wifichannels.append(WifiChannel(12, 2467, 2467, 20))
wifichannels.append(WifiChannel(13, 2472, 2472, 20))
wifichannels.append(WifiChannel(14, 2484, 2484, 20))

wifichannels.append(WifiChannel(36, 5195, 5180, 40))
wifichannels.append(WifiChannel(40, 5215, 5200, 40))
wifichannels.append(WifiChannel(44, 5235, 5220, 40))
wifichannels.append(WifiChannel(48, 5255, 5240, 40))
wifichannels.append(WifiChannel(52, 5275, 5260, 40))
wifichannels.append(WifiChannel(56, 5295, 5280, 40))
wifichannels.append(WifiChannel(60, 5315, 5300, 40))

wifichannels.append(WifiChannel(64, 5335, 5320, 80))
wifichannels.append(WifiChannel(68, 5355, 5340, 80))
wifichannels.append(WifiChannel(96, 5495, 5480, 80))
wifichannels.append(WifiChannel(100, 5515, 5500, 80))
wifichannels.append(WifiChannel(104, 5535, 5520, 80))
wifichannels.append(WifiChannel(108, 5555, 5540, 80))
wifichannels.append(WifiChannel(112, 5575, 5560, 80))
wifichannels.append(WifiChannel(116, 5595, 5580, 80))

wifichannels.append(WifiChannel(120, 5615, 5600, 80))
wifichannels.append(WifiChannel(124, 5635, 5620, 80))
wifichannels.append(WifiChannel(128, 5655, 5640, 80))
wifichannels.append(WifiChannel(132, 5675, 5660, 80))
wifichannels.append(WifiChannel(136, 5695, 5680, 80))
wifichannels.append(WifiChannel(140, 5715, 5700, 80))
wifichannels.append(WifiChannel(144, 5735, 5720, 80))
wifichannels.append(WifiChannel(149, 5760, 5745, 80))
wifichannels.append(WifiChannel(153, 5780, 5765, 80))
wifichannels.append(WifiChannel(157, 5800, 5785, 80))
wifichannels.append(WifiChannel(161, 5820, 5805, 80))
wifichannels.append(WifiChannel(165, 5840, 5825, 80))
wifichannels.append(WifiChannel(169, 5860, 5845, 80))
wifichannels.append(WifiChannel(173, 5880, 5865, 80))
wifichannels.append(WifiChannel(177, 5900, 5885, 80))

#wifichannels.reverse()

def change_channel(device, wifichannel):
    """ subprocess.run(["iw", device, "set", "freq",
                    str(wifichannel.control),
                    str(wifichannel.bandwidth),
                    str(wifichannel.center)])
 """
    subprocess.run(["iwconfig", device, "channel", str(wifichannel.channel)])

def set_monitor(device):
    subprocess.run(["ip", "link", "set", device, "down"])
    subprocess.run(["iw", device, "set", "monitor", "otherbss", "fcsfail"])
    subprocess.run(["ip", "link", "set", device, "up"])

running = True
keyboard.on_press_key("q", lambda _: globals().__setitem__('running',False))

def main():
    global running
    twofour=True
    five=True
    set_monitor(interface)
    wait_time=2000
    thread_stopping_wait_time=1000

    pcap_handle = Sniff(interface, filters="", count=300, promisc=1, monitor=-1, threaded=1, timeout=-1, immediate=1, snaplen=16394)


    while running:
        for channel in wifichannels:
            if not running:
                print()
                break

            if channel.channel < 36 and not twofour:
                continue
            elif channel.channel >= 36 and not five:
                continue

            print(f"Channel: {channel.channel}     \r", end='', flush=True)
            change_channel(interface, channel)

            time.sleep(1)

            try:
                os.mkdir(f"packets/{channel.channel}")
            except:
                pass
            
            pcap_handle.set_outpcap(f"packets/{channel.channel}/pcap.pcap")
            
            pcap_handle.run_capture_threaded()
            time.sleep(wait_time/1000)
            pcap_handle.stop_capture_threaded()

            capture_completed = pcap_handle.wait_for_thread(timeout=thread_stopping_wait_time/1000)

            if not capture_completed:
                print(f"Capture not stopped in {thread_stopping_wait_time/1000} seconds.")
                print("Waiting for the thread indefinitely, it may be busy or hanging.")
                pcap_handle.wait_for_thread()
            
            find_broca(f"packets/{channel.channel}/pcap.pcap")
        
        pcap_handle.close()
        break

def find_broca(file):
    bytes_to_check = 4
    trailing_bytes = 2
    search_for = ["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z"]
    packet_number = 0
    for len, t, pkt in rpcap(file):
        packet_number += 1

        testbytes = pkt[len-bytes_to_check-trailing_bytes:len-trailing_bytes]
        try:
            utf12_output = decode(testbytes)
        except:
            continue
        for chr in utf12_output:
            if chr in search_for:
                print(file)
                print(f"\tPacket Number: {packet_number}")
                print(f"\tCharacter: {chr}")

main()