#!/usr/bin/env python3

"""
Controller do Trabalho 4

Fluxo:

Switch
↓

Telemetria

↓

Decision Engine

↓

Switch Manager

↓

Nova regra P4
"""

import argparse
import socket
import struct
import time

from decision import DecisionEngine
from switch_manager import SwitchManager

ETH_P_ALL = 0x0003
TELEM_ETYPE = 0x9999


class Controller:

    def __init__(self, iface):

        self.iface = iface

        self.engine = DecisionEngine()

        self.switch = SwitchManager()

        self.window = 0


    def receive(self):

        sock = socket.socket(

            socket.AF_PACKET,

            socket.SOCK_RAW,

            socket.htons(ETH_P_ALL)

        )

        sock.bind((self.iface, 0))

        while True:

            raw, _ = sock.recvfrom(65535)

            result = self.parse(raw)

            if result is None:

                continue

            yield result


    def parse(self, raw):

        if len(raw) < 24:

            return None

        ether = struct.unpack(

            "!H",

            raw[12:14]

        )[0]

        if ether != TELEM_ETYPE:

            return None

        packets, bytes_, ttl, proto = struct.unpack(

            "!IIBB",

            raw[14:24]

        )

        return (

            packets,

            bytes_,

            ttl,

            proto

        )


    def execute(self):

        print()

        print("--------------------------------")

        print("Controller iniciado")

        print("--------------------------------")

        print()

        for packets, bytes_, ttl, proto in self.receive():

            self.window += 1

            decision = self.engine.decide(

                packets,

                bytes_,

                ttl,

                proto

            )

            print()

            print(f"Janela: {self.window}")

            print(f"Pacotes : {packets}")

            print(f"Bytes   : {bytes_}")

            print(f"TTL     : {ttl}")

            print(f"Proto   : {proto}")

            print()

            print(

                "AÇÃO:",

                decision.action

            )

            print(

                "Motivo:",

                decision.reason

            )

            flow = "10.0.1.1"

            #
            # Ações
            #

            if decision.action == "DROP":

                self.switch.install_drop(flow)

            elif decision.action == "REDIRECT":

                self.switch.install_redirect(flow)

            elif decision.action == "MARK_DSCP":

                self.switch.install_dscp(flow)

            else:

                self.switch.remove_rule(flow)

            time.sleep(0.05)


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(

        "--iface",

        default="h3-eth0"

    )

    args = parser.parse_args()

    controller = Controller(

        args.iface

    )

    controller.execute()


if __name__ == "__main__":

    main()