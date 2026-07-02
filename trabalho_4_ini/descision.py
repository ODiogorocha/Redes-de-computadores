#!/usr/bin/env python3

"""
decision.py

Implementa a política de decisão do Trabalho 4.

Recebe as métricas vindas da telemetria e determina
qual ação deverá ser instalada no switch.
"""

from dataclasses import dataclass


PACKET_THRESHOLD = 100
BYTE_THRESHOLD = 15000
TTL_THRESHOLD = 40


@dataclass
class Decision:

    action: str

    reason: str


class DecisionEngine:

    def __init__(self):

        self.last_action = "FORWARD"


    def decide(self,
               packets,
               bytes_,
               ttl,
               protocol):

        #
        # Fluxo muito pesado
        #

        if packets > PACKET_THRESHOLD:

            return Decision(

                action="DROP",

                reason=f"Pacotes acima do limite ({packets})"

            )

        #
        # Muitos bytes
        #

        if bytes_ > BYTE_THRESHOLD:

            return Decision(

                action="REDIRECT",

                reason=f"Bytes acima do limite ({bytes_})"

            )

        #
        # TTL muito pequeno
        #

        if ttl < TTL_THRESHOLD:

            return Decision(

                action="MARK_DSCP",

                reason=f"TTL crítico ({ttl})"

            )

        #
        # Tráfego normal
        #

        return Decision(

            action="FORWARD",

            reason="Fluxo normal"

        )


if __name__ == "__main__":

    engine = DecisionEngine()

    tests = [

        (20,1000,64,6),

        (150,4000,64,6),

        (20,30000,64,17),

        (20,1000,20,1)

    ]

    for t in tests:

        result = engine.decide(*t)

        print(result)