from utf12 import encode, decode
import os
import pathlib
from pylibpcap.pcap import rpcap

search_for = ["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z"]

pcap_files = []
packetsdir_sorted = os.listdir("packets.old.01")
packetsdir_sorted.sort()
for dir in packetsdir_sorted:
    channelDir = "packets.old.01/" + dir
    if not os.path.isdir(channelDir):
        continue
    for file in os.listdir(channelDir):
        filePath = channelDir + "/" + file
        if not os.path.isfile(filePath):
            continue
        if not pathlib.Path(filePath).suffix == ".pcap":
            continue
        pcap_files.append(filePath)

output_file = open("broca_old.csv", "w")
output_file.write("Filename,Packet Number,Character\n")

for file in pcap_files:
    packet_number = 0
    for len, t, pkt in rpcap(file):
        packet_number += 1

        testbytes = pkt[len-3-1:len-1]
        try:
            utf12_output = decode(testbytes)
        except:
            continue
        for chr in utf12_output:
            if chr in search_for:
                print(file)
                print(f"\tPacket Number: {packet_number}")
                print(f"\tCharacter: {chr}")
                output_file.write(f"{file},{packet_number},{chr}\n")
        
output_file.close()