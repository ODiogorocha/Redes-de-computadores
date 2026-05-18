#!/usr/bin/env python3
"""
dashboard.py  –  Dashboard Tkinter para visualização de telemetria P4
Substitui o collector.py: escuta na interface de h3 por pacotes com
EtherType 0x9999 e exibe as métricas em tempo real.

Estrutura do cabeçalho de telemetria (10 bytes após Ethernet):
  [0-3]  pkt_count      uint32 big-endian  – pacotes na janela
  [4-7]  byte_count     uint32 big-endian  – bytes na janela
  [8]    min_ttl        uint8              – TTL mínimo observado
  [9]    dominant_proto uint8              – protocolo dominante (1/6/17)

Execução dentro do host h3 no Mininet:
  sudo python3 dashboard.py --iface h3-eth0

  Ou pela CLI do Mininet:
  h3 sudo python3 dashboard.py --iface h3-eth0 &
"""

import argparse
import struct
import socket
import threading
import tkinter as tk
from collections import deque
from datetime import datetime

# ── Protocolo ─────────────────────────────────────────────────────────────────
ETH_P_ALL   = 0x0003
TELEM_ETYPE = 0x9999

PROTO_NAMES  = {1: "ICMP", 6: "TCP", 17: "UDP"}
PROTO_COLORS = {"ICMP": "#f97316", "TCP": "#22d3ee", "UDP": "#a78bfa", "?": "#94a3b8"}

# ── Paleta ────────────────────────────────────────────────────────────────────
BG      = "#0d1117"
BG2     = "#161b22"
BG3     = "#21262d"
ACCENT  = "#00ff99"
ACCENT2 = "#00ccff"
TEXT    = "#e6edf3"
DIM     = "#8b949e"
RED     = "#ff4d6d"
ORANGE  = "#f97316"
HISTORY = 30
GRAPH_H = 80


# ── Parsing ───────────────────────────────────────────────────────────────────
def parse_telemetry(raw: bytes):
    """Retorna (pkt_count, byte_count, min_ttl, dominant_proto) ou None."""
    if len(raw) < 24:
        return None
    etype = struct.unpack("!H", raw[12:14])[0]
    if etype != TELEM_ETYPE:
        return None
    pkt, byt, ttl, proto = struct.unpack("!IIBB", raw[14:24])
    return pkt, byt, ttl, proto

def proto_name(n: int) -> str:
    return PROTO_NAMES.get(n, "?")

def proto_color(n: int) -> str:
    return PROTO_COLORS.get(proto_name(n), PROTO_COLORS["?"])


# ── Widget: Sparkline ─────────────────────────────────────────────────────────
class Sparkline(tk.Canvas):
    def __init__(self, parent, color=ACCENT, **kw):
        super().__init__(parent, bg=BG3, highlightthickness=0,
                         height=GRAPH_H, **kw)
        self.color = color
        self.data  = deque([0] * HISTORY, maxlen=HISTORY)
        self.bind("<Configure>", lambda _e: self._redraw())

    def push(self, val: float):
        self.data.append(val)
        self._redraw()

    def _redraw(self):
        self.delete("all")
        W = self.winfo_width()
        H = self.winfo_height()
        if W < 2:
            return
        vals = list(self.data)
        mx   = max(vals) or 1
        step = W / (HISTORY - 1)
        pts  = [(i * step, H - (v / mx) * (H - 10) - 5)
                for i, v in enumerate(vals)]

        poly = [0, H] + [c for p in pts for c in p] + [W, H]
        self.create_polygon(poly, fill=self.color + "28", outline="")

        for i in range(len(pts) - 1):
            self.create_line(*pts[i], *pts[i + 1],
                             fill=self.color, width=2, smooth=True)

        lx, ly = pts[-1]
        self.create_oval(lx - 4, ly - 4, lx + 4, ly + 4,
                         fill=self.color, outline=BG3)


# ── Widget: MetricCard ────────────────────────────────────────────────────────
class MetricCard(tk.Frame):
    def __init__(self, parent, label: str, unit: str = "", color=ACCENT, **kw):
        super().__init__(parent, bg=BG2, **kw)
        tk.Frame(self, bg=color, height=3).pack(fill="x")
        body = tk.Frame(self, bg=BG2, padx=12, pady=10)
        body.pack(fill="both", expand=True)
        tk.Label(body, text=label.upper(), bg=BG2, fg=DIM,
                 font=("Courier", 8, "bold")).pack(anchor="w")
        self._var = tk.StringVar(value="—")
        tk.Label(body, textvariable=self._var, bg=BG2, fg=TEXT,
                 font=("Courier", 24, "bold")).pack(anchor="w", pady=(2, 0))
        tk.Label(body, text=unit, bg=BG2, fg=color,
                 font=("Courier", 8)).pack(anchor="w")
        self._spark = Sparkline(body, color=color)
        self._spark.pack(fill="x", pady=(8, 0))

    def update(self, display_val, raw: float = 0.0):
        self._var.set(str(display_val))
        self._spark.push(raw)


# ── Widget: ProtocolCard ──────────────────────────────────────────────────────
class ProtocolCard(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG2, **kw)
        tk.Frame(self, bg=ACCENT2, height=3).pack(fill="x")
        body = tk.Frame(self, bg=BG2, padx=12, pady=10)
        body.pack(fill="both", expand=True)
        tk.Label(body, text="PROTOCOLO DOMINANTE", bg=BG2, fg=DIM,
                 font=("Courier", 8, "bold")).pack(anchor="w")
        self._badge_var = tk.StringVar(value="  —  ")
        self._badge = tk.Label(body, textvariable=self._badge_var,
                               bg=BG3, fg=ACCENT2,
                               font=("Courier", 20, "bold"),
                               padx=16, pady=8)
        self._badge.pack(anchor="w", pady=(8, 12))
        tk.Label(body, text="Histórico:", bg=BG2, fg=DIM,
                 font=("Courier", 8)).pack(anchor="w")
        self._hist_var = tk.StringVar(value="")
        tk.Label(body, textvariable=self._hist_var,
                 bg=BG2, fg=DIM, font=("Courier", 8),
                 wraplength=200, justify="left").pack(anchor="w")
        self._hist: deque = deque(maxlen=10)

    def update(self, proto_num: int):
        name  = proto_name(proto_num)
        color = proto_color(proto_num)
        self._hist.append(name)
        self._badge_var.set(f"  {name}  ")
        self._badge.config(fg=color)
        self._hist_var.set(" › ".join(self._hist))


# ── Widget: LogPanel ──────────────────────────────────────────────────────────
class LogPanel(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG2, **kw)
        tk.Frame(self, bg="#334155", height=3).pack(fill="x")
        hdr = tk.Frame(self, bg=BG2, padx=12, pady=6)
        hdr.pack(fill="x")
        tk.Label(hdr, text="LOG DE JANELAS", bg=BG2, fg=DIM,
                 font=("Courier", 8, "bold")).pack(side="left")
        tk.Button(hdr, text="limpar", bg=BG3, fg=DIM,
                  font=("Courier", 8), relief="flat", cursor="hand2",
                  activebackground=BG3, activeforeground=ACCENT,
                  command=self._clear).pack(side="right")
        self._txt = tk.Text(self, bg=BG3, fg=DIM,
                            font=("Courier", 9), relief="flat",
                            state="disabled", padx=8, pady=4)
        self._txt.pack(fill="both", expand=True)
        sb = tk.Scrollbar(self, command=self._txt.yview,
                          bg=BG3, troughcolor=BG3, relief="flat")
        self._txt.config(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._txt.tag_config("ts",  foreground="#475569")
        self._txt.tag_config("win", foreground=ACCENT)
        self._txt.tag_config("val", foreground=TEXT)
        self._txt.tag_config("prt", foreground=ACCENT2)

    def append(self, win: int, pkt: int, byt: int, ttl: int, proto: int):
        avg = byt / pkt if pkt else 0
        ts  = datetime.now().strftime("%H:%M:%S")
        self._txt.config(state="normal")
        self._txt.insert("end", f"[{ts}] ", "ts")
        self._txt.insert("end", f"#{win:04d} ", "win")
        self._txt.insert("end",
            f"pkts={pkt}  bytes={byt}  avg={avg:.0f}B  ttl_min={ttl}  proto=",
            "val")
        self._txt.insert("end", f"{proto_name(proto)}\n", "prt")
        self._txt.see("end")
        self._txt.config(state="disabled")

    def _clear(self):
        self._txt.config(state="normal")
        self._txt.delete("1.0", "end")
        self._txt.config(state="disabled")


# ── Widget: StatusBar ─────────────────────────────────────────────────────────
class StatusBar(tk.Frame):
    def __init__(self, parent, iface: str, **kw):
        super().__init__(parent, bg="#0a0e14", **kw)
        self._dot = tk.Canvas(self, width=10, height=10,
                              bg="#0a0e14", highlightthickness=0)
        self._dot.pack(side="left", padx=(10, 4), pady=5)
        self._dot_id = self._dot.create_oval(1, 1, 9, 9,
                                             fill="#334155", outline="")
        self._status = tk.StringVar(value="Iniciando socket...")
        tk.Label(self, textvariable=self._status, bg="#0a0e14",
                 fg=DIM, font=("Courier", 9)).pack(side="left")
        tk.Label(self, text=f"iface: {iface}", bg="#0a0e14",
                 fg=DIM, font=("Courier", 9)).pack(side="right", padx=10)
        self._wins = tk.StringVar(value="0")
        tk.Label(self, textvariable=self._wins, bg="#0a0e14",
                 fg=ACCENT, font=("Courier", 9, "bold")).pack(side="right", padx=(0, 4))
        tk.Label(self, text="janelas:", bg="#0a0e14",
                 fg="#334155", font=("Courier", 9)).pack(side="right", padx=(10, 0))

    def set_live(self):
        self._status.set("Escutando pacotes de telemetria (EtherType 0x9999)...")
        self._dot.itemconfig(self._dot_id, fill=ACCENT)

    def set_error(self, msg: str):
        self._status.set(f"ERRO: {msg}")
        self._dot.itemconfig(self._dot_id, fill=RED)

    def tick(self, n: int):
        self._wins.set(str(n))


# ── App principal ─────────────────────────────────────────────────────────────
class Dashboard(tk.Tk):
    def __init__(self, iface: str):
        super().__init__()
        self._iface  = iface
        self._window = 0
        self._queue  = []
        self._lock   = threading.Lock()
        self._build()
        threading.Thread(target=self._recv_loop, daemon=True).start()
        self._poll()

    def _build(self):
        self.title("P4 Telemetry Dashboard – UFSM")
        self.configure(bg=BG)
        self.geometry("900x680")
        self.minsize(760, 560)
        self.resizable(True, True)

        # Header
        hdr = tk.Frame(self, bg=BG, pady=14)
        hdr.pack(fill="x", padx=20)
        tk.Label(hdr, text="◈", bg=BG, fg=ACCENT,
                 font=("Courier", 18, "bold")).pack(side="left", padx=(0, 8))
        tk.Label(hdr, text="P4 TELEMETRY", bg=BG, fg=TEXT,
                 font=("Courier", 16, "bold")).pack(side="left")
        tk.Label(hdr, text="DASHBOARD", bg=BG, fg=ACCENT,
                 font=("Courier", 16, "bold")).pack(side="left", padx=(6, 0))
        self._ts_var = tk.StringVar(value="")
        tk.Label(hdr, textvariable=self._ts_var, bg=BG, fg=DIM,
                 font=("Courier", 9)).pack(side="right")

        tk.Frame(self, bg=BG3, height=1).pack(fill="x", padx=20)

        # Cards (linha 1)
        cards = tk.Frame(self, bg=BG, padx=20, pady=14)
        cards.pack(fill="x")
        cards.columnconfigure((0, 1, 2, 3), weight=1, uniform="c")

        self._c_pkt = MetricCard(cards, "Pacotes",    "pkts / janela",  ACCENT)
        self._c_byt = MetricCard(cards, "Bytes",      "bytes / janela", ACCENT2)
        self._c_ttl = MetricCard(cards, "TTL Mínimo", "hop limit",      RED)
        self._c_avg = MetricCard(cards, "Tam. Médio", "bytes / pkt",    ORANGE)

        self._c_pkt.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        self._c_byt.grid(row=0, column=1, sticky="nsew", padx=(5, 5))
        self._c_ttl.grid(row=0, column=2, sticky="nsew", padx=(5, 5))
        self._c_avg.grid(row=0, column=3, sticky="nsew", padx=(5, 0))

        # Linha 2: protocolo + log
        row2 = tk.Frame(self, bg=BG, padx=20)
        row2.pack(fill="both", expand=True, pady=(0, 8))
        row2.columnconfigure(0, weight=1)
        row2.columnconfigure(1, weight=3)
        row2.rowconfigure(0, weight=1)

        self._proto = ProtocolCard(row2)
        self._proto.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        self._log = LogPanel(row2)
        self._log.grid(row=0, column=1, sticky="nsew", padx=(5, 0))

        # Status bar
        self._status = StatusBar(self, iface=self._iface)
        self._status.pack(fill="x", side="bottom")

    def _recv_loop(self):
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                 socket.htons(ETH_P_ALL))
            sock.bind((self._iface, 0))
        except PermissionError:
            with self._lock:
                self._queue.append(("err", "Permissão negada. Execute com sudo."))
            return
        except OSError as e:
            with self._lock:
                self._queue.append(("err", str(e)))
            return

        with self._lock:
            self._queue.append(("live",))

        while True:
            try:
                raw, _ = sock.recvfrom(65535)
                result = parse_telemetry(raw)
                if result is None:
                    continue
                with self._lock:
                    self._queue.append(("data", *result))
            except Exception:
                continue

    def _poll(self):
        with self._lock:
            items, self._queue = self._queue, []

        for item in items:
            if item[0] == "live":
                self._status.set_live()
            elif item[0] == "err":
                self._status.set_error(item[1])
            elif item[0] == "data":
                _, pkt, byt, ttl, proto = item
                self._update(pkt, byt, ttl, proto)

        self._ts_var.set(datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.after(150, self._poll)

    def _update(self, pkt: int, byt: int, ttl: int, proto: int):
        self._window += 1
        avg = byt / pkt if pkt else 0
        self._c_pkt.update(pkt,                           raw=pkt)
        self._c_byt.update(f"{byt:,}".replace(",", "."),  raw=byt)
        self._c_ttl.update(ttl,                           raw=ttl)
        self._c_avg.update(f"{avg:.0f}",                  raw=avg)
        self._proto.update(proto)
        self._log.append(self._window, pkt, byt, ttl, proto)
        self._status.tick(self._window)


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Dashboard Tkinter de telemetria P4 – Trabalho 2 UFSM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso no Mininet:

  # Na CLI do Mininet (abre janela no display do host):
  h3 sudo python3 dashboard.py --iface h3-eth0 &

  # Ou abrindo xterm de h3 e rodando lá dentro:
  xterm h3
  > sudo python3 dashboard.py --iface h3-eth0
        """
    )
    ap.add_argument(
        "--iface", default="h3-eth0",
        help="Interface de rede de h3 (padrão: h3-eth0)"
    )
    args = ap.parse_args()
    Dashboard(iface=args.iface).mainloop()