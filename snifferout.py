import argparse
from scapy.all import *


class Sniffer:
    def __init__(self, args):
        self.args = args

    def __call__(self, packet):
        with open(self.args.file, "a") as f:
            if self.args.verbose:
                f.write(str(packet))
            else:
                f.write(packet.summary())
            f.write("\n")

    def run_forever(self):
        sniff(iface=self.args.interface, prn=self, store=0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', default=False, action='store_true', help='be more talkative')
    parser.add_argument('-i', '--interface', type=str, required=True, help='network interface name')
    parser.add_argument('-f', '--file', type=str, required=True, help='file name to save the packets')
    args = parser.parse_args()
    sniffer = Sniffer(args)
    sniffer.run_forever()

