#!/usr/bin/env python3

"""
switch_manager.py

Responsável por instalar, atualizar e remover
regras automaticamente no switch BMv2.

O controlador nunca modifica regras manualmente.
Todas as alterações são consequência da telemetria.
"""

import subprocess


class SwitchManager:

    def __init__(self,
                 thrift_port=9090):

        self.thrift_port = thrift_port

        self.installed_rules = {}


    def execute(self, command):

        process = subprocess.Popen(
            [
                "simple_switch_CLI",
                "--thrift-port",
                str(self.thrift_port)
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        stdout, stderr = process.communicate(command)

        return stdout, stderr


    def install_drop(self,
                     flow):

        if flow in self.installed_rules:

            return

        cmd = f"""
table_add MyIngress.flow_control drop_flow {flow} =>
"""

        self.execute(cmd)

        self.installed_rules[flow] = "DROP"

        print(f"[SWITCH] DROP instalado para {flow}")


    def install_redirect(self,
                         flow,
                         port=3):

        if flow in self.installed_rules:

            return

        cmd = f"""
table_add MyIngress.flow_control redirect_flow {flow} => {port}
"""

        self.execute(cmd)

        self.installed_rules[flow] = "REDIRECT"

        print(f"[SWITCH] REDIRECT instalado para {flow}")


    def install_dscp(self,
                     flow,
                     value=10):

        if flow in self.installed_rules:

            return

        cmd = f"""
table_add MyIngress.flow_control set_dscp {flow} => {value}
"""

        self.execute(cmd)

        self.installed_rules[flow] = "DSCP"

        print(f"[SWITCH] DSCP instalado para {flow}")


    def remove_rule(self,
                    flow):

        if flow not in self.installed_rules:

            return

        cmd = f"""
table_delete MyIngress.flow_control {flow}
"""

        self.execute(cmd)

        del self.installed_rules[flow]

        print(f"[SWITCH] Regra removida {flow}")


    def clear_all(self):

        for flow in list(self.installed_rules.keys()):

            self.remove_rule(flow)