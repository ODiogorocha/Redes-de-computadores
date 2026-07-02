#!/usr/bin/env python3

"""
traffic_generator.py

Gerador de tráfego utilizado para demonstrar
o funcionamento do controlador.

São implementados quatro modos:

normal
udp
tcp
flood
"""

import argparse
import subprocess
import time


class TrafficGenerator:

    def normal(self):

        print()

        print("Gerando tráfego ICMP normal...")

        subprocess.run([

            "ping",

            "-c",

            "20",

            "10.0.2.2"

        ])


    def udp(self):

        print()

        print("Gerando UDP...")

        subprocess.run([

            "iperf3",

            "-u",

            "-c",

            "10.0.2.2",

            "-b",

            "5M",

            "-t",

            "20"

        ])


    def tcp(self):

        print()

        print("Gerando TCP...")

        subprocess.run([

            "iperf3",

            "-c",

            "10.0.2.2",

            "-t",

            "20"

        ])


    def flood(self):

        print()

        print("Gerando tráfego intenso...")

        subprocess.run([

            "iperf3",

            "-u",

            "-c",

            "10.0.2.2",

            "-b",

            "100M",

            "-t",

            "30"

        ])


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(

        "--mode",

        choices=[

            "normal",

            "udp",

            "tcp",

            "flood"

        ],

        default="normal"

    )

    args = parser.parse_args()

    generator = TrafficGenerator()

    if args.mode == "normal":

        generator.normal()

    elif args.mode == "udp":

        generator.udp()

    elif args.mode == "tcp":

        generator.tcp()

    elif args.mode == "flood":

        generator.flood()


if __name__ == "__main__":

    main()