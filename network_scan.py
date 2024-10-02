from scapy.all import *
from pyfiglet import figlet_format
from argparse import ArgumentParser

# print ascii banner
ascii_banner = figlet_format("Network  Scanner")
print(ascii_banner)

arp = ARP()
ether = Ether()

parser = ArgumentParser(description="Python network scanner tool")

def get_arguments():
  parser.add_argument("--host", dest="host", help="Network address to be scanned")
  args = parser.parse_args()
  return args

args = get_arguments()

arp.pdst = args.host
ether.dst = "ff:ff:ff:ff:ff:ff"

packet = ether/arp

answer = srp(packet, timeout=5)[0]

print("-----------------------------------\nIP Address\tMAC Address\n-----------------------------------")
for snd, rcv in answer:
  print(f"{rcv.psrc} \t {rcv.src}")