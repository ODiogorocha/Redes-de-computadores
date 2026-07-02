#!/usr/bin/env python3
"""
streamlit_dashboard.py — Trabalho 4 (UFSM)
============================================

Visualizador web (Streamlit) da telemetria e das decisões do
controlador. Substitui o dashboard.py em Tkinter, que exige um
display gráfico local e é incômodo de usar quando o trabalho é
acessado por SSH.

Como funciona:
  - Um socket cru (AF_PACKET) é aberto em background na interface
    de h3, escutando exatamente a mesma telemetria que controller.py
    recebe (janela global e alertas de fluxo).
  - As funções de parsing e a política de decisão são importadas
    diretamente de controller.py, para exibir SEMPRE o mesmo estado
    (NONE/MARKED/BLOCKED) que o controlador está de fato aplicando
    no switch — sem duplicar/desalinhar a lógica.
  - A página web é servida pelo Streamlit e atualiza sozinha
    (st.fragment com run_every).

COMO EXECUTAR (dentro do Mininet, no host h3, precisa de sudo por
causa do socket cru):

    h3 sudo $(which streamlit) run streamlit_dashboard.py \\
        --server.address 0.0.0.0 --server.port 8501

COMO ACESSAR DO SEU PC (você está em SSH no servidor):
    O Streamlit fica rodando no servidor remoto, não no seu PC. Para
    abrir no navegador da sua máquina, crie um túnel SSH que
    redireciona uma porta local para a porta 8501 do servidor:

        # no SEU computador (nova aba de terminal, fora do servidor):
        ssh -L 8501:localhost:8501 usuario@endereco_do_servidor

    Mantenha essa conexão aberta e acesse, no navegador local:

        http://localhost:8501

    (Se o servidor estiver atrás de outro salto/bastion, encadeie o
    -L na mesma linha do ssh que você já usa para entrar no servidor.)
"""

import collections
import socket
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

# garante que "import controller" funcione independente do cwd
sys.path.insert(0, str(Path(__file__).resolve().parent))

from controller import (  # noqa: E402  (reaproveita parsing e política do Trabalho 4)
    BLOCK_PKT_THRESHOLD,
    ETH_P_ALL,
    FLOW_ALERT_ETYPE,
    IDLE_TIMEOUT_SEC,
    MARK_DSCP_VALUE,
    MARK_PKT_THRESHOLD,
    PROTO_NAMES,
    STATE_BLOCKED,
    STATE_MARKED,
    STATE_NONE,
    TELEM_ETYPE,
    decide_state,
    parse_flow_alert,
    parse_window_telemetry,
)

HISTORY = 300

st.set_page_config(page_title="P4 Telemetry Dashboard — Trabalho 4",
                    page_icon="📡", layout="wide")


# ═══════════════════════ Sniffer em background (singleton) ═════════════════
class TelemetryStore:
    def __init__(self, iface: str):
        self.iface = iface
        self.lock = threading.Lock()
        self.window_history: collections.deque = collections.deque(maxlen=HISTORY)
        self.flow_alert_log: collections.deque = collections.deque(maxlen=HISTORY)
        self.flow_states: dict = {}   # src_ip -> {state, pkt_count, byte_count, last_seen}
        self.status = "iniciando"
        self.error = None
        threading.Thread(target=self._sniff, daemon=True).start()

    def _sniff(self):
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                 socket.htons(ETH_P_ALL))
            sock.bind((self.iface, 0))
        except PermissionError:
            with self.lock:
                self.error = ("Permissão negada ao abrir socket cru. "
                              "Rode o Streamlit com sudo.")
            return
        except OSError as e:
            with self.lock:
                self.error = f"Não foi possível abrir {self.iface}: {e}"
            return

        with self.lock:
            self.status = "ativo"

        while True:
            try:
                raw, _ = sock.recvfrom(65535)
            except Exception as e:
                with self.lock:
                    self.error = str(e)
                continue

            alert = parse_flow_alert(raw)
            if alert is not None:
                src_ip, pkt, byt, ttl = alert
                now = time.time()
                with self.lock:
                    self.flow_alert_log.append({
                        "hora": datetime.now().strftime("%H:%M:%S"),
                        "IP origem": src_ip, "pacotes": pkt,
                        "bytes": byt, "ttl_min": ttl,
                    })
                    f = self.flow_states.setdefault(src_ip, {})
                    f["pkt_count"]  = pkt
                    f["byte_count"] = byt
                    f["last_seen"]  = now
                    f["state"]      = decide_state(pkt, byt)
                continue

            window = parse_window_telemetry(raw)
            if window is not None:
                pkt, byt, ttl, proto = window
                with self.lock:
                    self.window_history.append({
                        "hora": datetime.now().strftime("%H:%M:%S"),
                        "pacotes": pkt, "bytes": byt, "ttl_min": ttl,
                        "protocolo": PROTO_NAMES.get(proto, f"?({proto})"),
                    })

    def snapshot(self):
        now = time.time()
        with self.lock:
            flows = []
            for src, f in self.flow_states.items():
                idle = now - f.get("last_seen", now)
                estado = f.get("state", STATE_NONE)
                if estado != STATE_NONE and idle > IDLE_TIMEOUT_SEC:
                    # o controller.py já removeria a regra por inatividade;
                    # refletimos isso aqui só para exibição
                    estado = STATE_NONE
                flows.append({
                    "IP origem": src,
                    "Pacotes (acum.)": f.get("pkt_count", 0),
                    "Bytes (acum.)": f.get("byte_count", 0),
                    "Estado": estado,
                    "Última telemetria (s)": round(idle, 1),
                })
            return (
                list(self.window_history),
                list(self.flow_alert_log),
                flows,
                self.status,
                self.error,
            )


@st.cache_resource(show_spinner=False)
def get_store(iface: str) -> TelemetryStore:
    return TelemetryStore(iface)


# ══════════════════════════════ Sidebar ═════════════════════════════════════
with st.sidebar:
    st.header("⚙️ Configuração")
    iface = st.text_input("Interface de rede (em h3)", value="h3-eth0")
    st.caption("Deve ser a mesma interface usada pelo controller.py "
              "(ex.: h3-eth0).")

    st.markdown("---")
    st.markdown("**Política de decisão (controller.py)**")
    st.write(f"🟡 Marca (DSCP={MARK_DSCP_VALUE}) a partir de "
            f"**{MARK_PKT_THRESHOLD}** pacotes")
    st.write(f"🔴 Bloqueia a partir de **{BLOCK_PKT_THRESHOLD}** pacotes")
    st.write(f"⚪ Remove a regra após **{IDLE_TIMEOUT_SEC:.0f}s** sem telemetria")

    st.markdown("---")
    st.caption(
        "Acessando por SSH? Rode este dashboard no servidor e crie um túnel "
        "no seu PC:\n\n"
        "`ssh -L 8501:localhost:8501 usuario@servidor`\n\n"
        "Depois abra **http://localhost:8501** no navegador local."
    )

store = get_store(iface)


# ══════════════════════════════ Corpo da página ═════════════════════════════
st.title("📡 P4 Telemetry Dashboard — Trabalho 4")
st.caption("Telemetria de janela global (monitoramento) + telemetria por "
          "fluxo e decisão automática do controlador (marcar/bloquear/remover).")


@st.fragment(run_every=1)
def live_view():
    window_hist, flow_alerts, flows, status, error = store.snapshot()

    if error:
        st.error(f"🔌 {error}")
    elif status != "ativo":
        st.info("Aguardando o socket abrir e a primeira telemetria chegar...")
    else:
        st.success(f"🟢 Recebendo telemetria em `{iface}`")

    st.subheader("Telemetria de janela global")
    if window_hist:
        last = window_hist[-1]
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Pacotes / janela", last["pacotes"])
        c2.metric("Bytes / janela", f'{last["bytes"]:,}'.replace(",", "."))
        c3.metric("TTL mínimo", last["ttl_min"])
        c4.metric("Protocolo dominante", last["protocolo"])

        df = pd.DataFrame(window_hist)
        col_a, col_b = st.columns(2)
        with col_a:
            st.caption("Pacotes por janela")
            st.line_chart(df, x="hora", y="pacotes", height=220)
        with col_b:
            st.caption("Bytes por janela")
            st.line_chart(df, x="hora", y="bytes", height=220)
    else:
        st.write("_Nenhuma telemetria de janela recebida ainda._")

    st.subheader("Fluxos monitorados e decisão automática")
    if flows:
        fdf = pd.DataFrame(flows).sort_values("Pacotes (acum.)", ascending=False)

        def cor_estado(v):
            return {
                STATE_NONE:    "",
                STATE_MARKED:  "background-color:#fff3cd; color:#7a5b00;",
                STATE_BLOCKED: "background-color:#f8d7da; color:#7a1f27;",
            }.get(v, "")

        st.dataframe(
            fdf.style.map(cor_estado, subset=["Estado"]),
            use_container_width=True, hide_index=True,
        )
    else:
        st.write("_Nenhum fluxo reportado ainda — gere tráfego com "
                 "traffic_gen.py._")

    st.subheader("Últimos alertas de fluxo (bruto)")
    if flow_alerts:
        st.dataframe(
            pd.DataFrame(list(reversed(flow_alerts))[:30]),
            use_container_width=True, hide_index=True, height=260,
        )
    else:
        st.write("_Sem alertas de fluxo até o momento._")


live_view()
