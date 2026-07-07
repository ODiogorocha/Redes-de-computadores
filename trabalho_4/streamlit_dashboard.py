import streamlit as st
import pandas as pd
import time
import json
import os

st.set_page_config(
    page_title="Monitoramento P4",
    page_icon="=>",
    layout="wide"
)

# Inicialização do banco de dados temporário na memória da página
if 'history' not in st.session_state:
    st.session_state.history = pd.DataFrame(columns=['Janela Temporal', 'Taxa de Tráfego (pps)', 'Vazão de Rede (Kbps)'])
    st.session_state.contador = 0

SHARED_FILE = "shared_metrics.json"

# Valores padrão de fallback caso o gerador esteja desligado
pps_atual = 0
kbps_atual = 0.0
perfil = "Nenhum (Rede Ociosa)"
status_gerador = " Inativo"

# Lê os dados em tempo real gerados pelo tráfego automático
if os.path.exists(SHARED_FILE):
    try:
        with open(SHARED_FILE, 'r') as f:
            dados_reais = json.load(f)
            # Evita ler dados velhos se o gerador travar
            if time.time() - dados_reais.get("timestamp", 0) < 4:
                pps_atual = dados_reais.get("pps", 0)
                kbps_atual = dados_reais.get("kbps", 0.0)
                perfil = dados_reais.get("perfil_atual", perfil)
                status_gerador = dados_reais.get("status_gerador", status_gerador)
    except:
        pass

# Atualiza estrutura do gráfico de linhas/área
st.session_state.contador += 1
nova_metrica = pd.DataFrame({
    'Janela Temporal': [st.session_state.contador],
    'Taxa de Tráfego (pps)': [pps_atual],
    'Vazão de Rede (Kbps)': [kbps_atual]
})

st.session_state.history = pd.concat([st.session_state.history, nova_metrica], ignore_index=True)
if len(st.session_state.history) > 40:
    st.session_state.history = st.session_state.history.iloc[1:]

# --- INTERFACE GRÁFICA ---
st.title("=> Monitoramento de Telemetria e Controle P4 em Tempo Real")
st.caption("Métricas extraídas via clonagem de frames INT (In-band Network Telemetry) no plano de dados — UFSM")

st.markdown("---")

# Cards de Métricas
c1, c2, c3, c4 = st.columns(4)
with c1:
    st.metric("Status do Switch s1", " Conectado")
with c2:
    st.metric("Taxa de Tráfego", f"{pps_atual} pps", delta=f"{pps_atual - 20} pps" if pps_atual > 30 else None)
with c3:
    st.metric("Vazão Atual", f"{kbps_atual} Kbps")
with c4:
    st.metric("Gerador de Fluxos", status_gerador)

st.markdown("---")

st.subheader("=> Comportamento Dinâmico do Plano de Dados")
g1, g2 = st.columns(2)

with g1:
    st.markdown("**Frequência de Pacotes Processados (PPS)**")
    st.area_chart(st.session_state.history.set_index('Janela Temporal')['Taxa de Tráfego (pps)'], height=230)

with g2:
    st.markdown("**Largura de Banda Ocupada (Kbps)**")
    st.area_chart(st.session_state.history.set_index('Janela Temporal')['Vazão de Rede (Kbps)'], height=230)

st.markdown("---")

t1, t2 = st.columns(2)

with t1:
    st.subheader(" Estado de Fluxo Corrente")
    st.write(f"Perfil Detectado pelo Coletor: **{perfil}**")
    
    status_acao = "X DROP (Bloqueio Automático)" if pps_atual > 70 else " FORWARD (Liberado)"
    
    tabela_fluxo = pd.DataFrame({
        'Host Origem': ['10.0.0.1'],
        'Destino': ['10.0.0.2'],
        'Métrica Coletada': [f"{pps_atual} pacotes/s"],
        'Decisão P4 Ingress': [status_acao]
    })
    st.dataframe(tabela_fluxo, use_container_width=True)

with t2:
    st.subheader(" Tabela Runtime P4 (Mitigação Dinâmica)")
    if pps_atual > 70:
        st.error(" ALERTA: Taxa limite de segurança estourada! Injetando comando DROP.")
        regras_ativas = pd.DataFrame({
            'Tabela Switch': ['bloqueio_ip'],
            'Match Key': ['10.0.0.1 (h1)'],
            'Action': ['drop()'],
            'Policiamento': ['Automático']
        })
        st.table(regras_ativas)
    else:
        st.success(" Sistema Seguro. Nenhuma anomalia de tráfego registrada.")

time.sleep(0.8)
st.rerun()