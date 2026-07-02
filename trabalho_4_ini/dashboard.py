#!/usr/bin/env python3

import argparse
import socket
import struct
import threading
import tkinter as tk

from collections import deque
from datetime import datetime

ETH_P_ALL = 0x0003
TELEM_ETYPE = 0x9999

PROTO_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

PROTO_COLORS = {
    "ICMP": "#f97316",
    "TCP": "#22d3ee",
    "UDP": "#a78bfa",
    "?": "#94a3b8"
}

ACTION_COLORS = {
    "FORWARD": "#22c55e",
    "DROP": "#ef4444",
    "REDIRECT": "#3b82f6",
    "MARK_DSCP": "#eab308"
}

BG = "#0d1117"
BG2 = "#161b22"
BG3 = "#21262d"

ACCENT = "#00ff99"
ACCENT2 = "#00ccff"

TEXT = "#e6edf3"
DIM = "#8b949e"

RED = "#ff4d6d"
ORANGE = "#f97316"

HISTORY = 30

GRAPH_H = 80


def proto_name(value):

    return PROTO_NAMES.get(value, "?")


def proto_color(value):

    return PROTO_COLORS.get(

        proto_name(value),

        PROTO_COLORS["?"]

    )


def parse_telemetry(raw):

    if len(raw) < 26:

        return None

    try:

        ether_type = struct.unpack(

            "!H",

            raw[12:14]

        )[0]

        if ether_type != TELEM_ETYPE:

            return None

        packets, bytes_, ttl, proto, reserved = struct.unpack(

            "!IIBBH",

            raw[14:26]

        )

        return (

            packets,

            bytes_,

            ttl,

            proto

        )

    except:

        return None

class Sparkline(tk.Canvas):

    def __init__(self,
                 parent,
                 color=ACCENT,
                 **kwargs):

        super().__init__(

            parent,

            bg=BG3,

            highlightthickness=0,

            height=GRAPH_H,

            **kwargs

        )

        self.color = color

        self.values = deque(

            [0] * HISTORY,

            maxlen=HISTORY

        )

        self.bind(

            "<Configure>",

            lambda e: self.redraw()

        )


    def push(self, value):

        self.values.append(value)

        self.redraw()


    def redraw(self):

        self.delete("all")

        width = self.winfo_width()

        height = self.winfo_height()

        if width < 5:

            return

        maximum = max(self.values)

        if maximum == 0:

            maximum = 1

        step = width / (HISTORY - 1)

        points = []

        for i, value in enumerate(self.values):

            x = i * step

            y = height - (value / maximum) * (height - 10) - 5

            points.append((x, y))

        for i in range(len(points) - 1):

            self.create_line(

                *points[i],

                *points[i + 1],

                fill=self.color,

                width=2,

                smooth=True

            )

        x, y = points[-1]

        self.create_oval(

            x - 4,

            y - 4,

            x + 4,

            y + 4,

            fill=self.color,

            outline=""

        )
class MetricCard(tk.Frame):

    def __init__(

        self,

        parent,

        title,

        unit="",

        color=ACCENT

    ):

        super().__init__(

            parent,

            bg=BG2

        )

        tk.Frame(

            self,

            bg=color,

            height=3

        ).pack(fill="x")

        body = tk.Frame(

            self,

            bg=BG2,

            padx=10,

            pady=10

        )

        body.pack(

            fill="both",

            expand=True

        )

        tk.Label(

            body,

            text=title.upper(),

            bg=BG2,

            fg=DIM,

            font=("Courier",9,"bold")

        ).pack(anchor="w")

        self.value = tk.StringVar()

        tk.Label(

            body,

            textvariable=self.value,

            bg=BG2,

            fg=TEXT,

            font=("Courier",24,"bold")

        ).pack(anchor="w")

        tk.Label(

            body,

            text=unit,

            bg=BG2,

            fg=color,

            font=("Courier",8)

        ).pack(anchor="w")

        self.spark = Sparkline(

            body,

            color=color

        )

        self.spark.pack(

            fill="x",

            pady=8

        )


    def update(

        self,

        value,

        raw

    ):

        self.value.set(str(value))

        self.spark.push(raw)
class DecisionCard(tk.Frame):

    def __init__(self,parent):

        super().__init__(

            parent,

            bg=BG2

        )

        tk.Frame(

            self,

            bg="#6366f1",

            height=3

        ).pack(fill="x")

        body = tk.Frame(

            self,

            bg=BG2,

            padx=12,

            pady=12

        )

        body.pack(

            fill="both",

            expand=True

        )

        tk.Label(

            body,

            text="AÇÃO DO CONTROLADOR",

            bg=BG2,

            fg=DIM,

            font=("Courier",9,"bold")

        ).pack(anchor="w")

        self.action = tk.StringVar()

        self.reason = tk.StringVar()

        self.rules = tk.StringVar()

        self.label = tk.Label(

            body,

            textvariable=self.action,

            bg=BG2,

            fg=ACTION_COLORS["FORWARD"],

            font=("Courier",24,"bold")

        )

        self.label.pack(anchor="w")

        tk.Label(

            body,

            textvariable=self.reason,

            bg=BG2,

            fg=TEXT,

            font=("Courier",10)

        ).pack(anchor="w")

        tk.Label(

            body,

            textvariable=self.rules,

            bg=BG2,

            fg=ACCENT,

            font=("Courier",10)

        ).pack(anchor="w")

        self.update(

            "FORWARD",

            "Inicializando controlador",

            0

        )


    def update(

        self,

        action,

        reason,

        rules

    ):

        self.action.set(action)

        self.reason.set(reason)

        self.rules.set(

            f"Regras instaladas: {rules}"

        )

        self.label.config(

            fg=ACTION_COLORS.get(

                action,

                TEXT

            )

        )
class ProtocolCard(tk.Frame):

    def __init__(self,parent):

        super().__init__(

            parent,

            bg=BG2

        )

        tk.Frame(

            self,

            bg=ACCENT2,

            height=3

        ).pack(fill="x")

        body = tk.Frame(

            self,

            bg=BG2,

            padx=12,

            pady=10

        )

        body.pack(

            fill="both",

            expand=True

        )

        tk.Label(

            body,

            text="PROTOCOLO DOMINANTE",

            bg=BG2,

            fg=DIM,

            font=("Courier",9,"bold")

        ).pack(anchor="w")

        self.protocol = tk.StringVar()

        self.badge = tk.Label(

            body,

            textvariable=self.protocol,

            bg=BG3,

            fg=ACCENT2,

            font=("Courier",22,"bold"),

            padx=20,

            pady=10

        )

        self.badge.pack(anchor="w")

        self.update(6)


    def update(self,proto):

        name = proto_name(proto)

        self.protocol.set(name)

        self.badge.config(

            fg=proto_color(proto)

        )
class LogPanel(tk.Frame):

    def __init__(self, parent):

        super().__init__(parent, bg=BG2)

        tk.Frame(
            self,
            bg="#64748b",
            height=3
        ).pack(fill="x")

        tk.Label(
            self,
            text="LOG DE TELEMETRIA",
            bg=BG2,
            fg=DIM,
            font=("Courier", 10, "bold")
        ).pack(anchor="w", padx=10, pady=(10, 0))

        self.text = tk.Text(
            self,
            bg=BG3,
            fg=TEXT,
            height=14,
            font=("Courier", 9),
            relief="flat"
        )

        scrollbar = tk.Scrollbar(
            self,
            command=self.text.yview
        )

        self.text.configure(
            yscrollcommand=scrollbar.set
        )

        self.text.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(10, 0),
            pady=10
        )

        scrollbar.pack(
            side="right",
            fill="y",
            pady=10
        )

        self.text.configure(state="disabled")
            def add(
        self,
        packets,
        bytes_,
        ttl,
        proto,
        action
    ):

        now = datetime.now().strftime("%H:%M:%S")

        line = (
            f"[{now}] "
            f"PKT={packets} "
            f"BYTES={bytes_} "
            f"TTL={ttl} "
            f"PROTO={proto_name(proto)} "
            f"AÇÃO={action}\n"
        )

        self.text.configure(state="normal")

        self.text.insert(
            "end",
            line
        )

        self.text.see("end")

        self.text.configure(state="disabled")
class StatusBar(tk.Frame):

    def __init__(self,parent):

        super().__init__(
            parent,
            bg=BG2
        )

        self.message = tk.StringVar()

        self.message.set("Aguardando telemetria...")

        self.label = tk.Label(

            self,

            textvariable=self.message,

            bg=BG2,

            fg=ACCENT,

            anchor="w",

            padx=10

        )

        self.label.pack(
            fill="x"
        )


    def update(self,text):

        self.message.set(text)
class Dashboard:

    def __init__(

        self,

        iface

    ):

        self.iface = iface

        self.root = tk.Tk()

        self.root.title(

            "Controlador de Telemetria P4"

        )

        self.root.geometry(

            "1500x850"

        )

        self.root.configure(

            bg=BG

        )

        self.packets = MetricCard(

            self.root,

            "Pacotes",

            color="#22c55e"

        )

        self.bytes = MetricCard(

            self.root,

            "Bytes",

            color="#06b6d4"

        )

        self.ttl = MetricCard(

            self.root,

            "TTL",

            color="#ef4444"

        )

        self.average = MetricCard(

            self.root,

            "Tamanho Médio",

            color="#f59e0b"

        )

        self.protocol = ProtocolCard(

            self.root

        )

        self.decision = DecisionCard(

            self.root

        )

        self.log = LogPanel(

            self.root

        )

        self.status = StatusBar(

            self.root

        )

        self.build()
            def build(self):

        top = tk.Frame(

            self.root,

            bg=BG

        )

        top.pack(

            fill="x",

            padx=10,

            pady=10

        )

        self.packets.grid(

            row=0,

            column=0,

            padx=5,

            sticky="nsew"

        )

        self.bytes.grid(

            row=0,

            column=1,

            padx=5,

            sticky="nsew"

        )

        self.ttl.grid(

            row=0,

            column=2,

            padx=5,

            sticky="nsew"

        )

        self.average.grid(

            row=0,

            column=3,

            padx=5,

            sticky="nsew"

        )

        for i in range(4):

            top.grid_columnconfigure(

                i,

                weight=1

            )

        self.packets.master = top
        self.bytes.master = top
        self.ttl.master = top
        self.average.master = top

        self.packets.pack_propagate(False)