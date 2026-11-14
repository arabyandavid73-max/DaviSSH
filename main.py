import sys
import os
import json
import queue
import threading
import hashlib

import paramiko

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QPlainTextEdit, QListWidget, QMessageBox,
    QFrame, QInputDialog
)


APP_NAME = "DaviSSH"
GREEN = "#00e676"
BG = "#0b0e0d"
CARD = "#151a18"
TEXT = "#e8f5ed"

CONFIG_DIR = os.path.join(
    os.path.expanduser("~"), ".davissh"
)
os.makedirs(CONFIG_DIR, exist_ok=True)

SERVERS_FILE = os.path.join(CONFIG_DIR, "servers.json")
KNOWN_HOSTS = os.path.join(CONFIG_DIR, "known_hosts")


class HostKeyPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, worker):
        self.worker = worker

    def missing_host_key(self, client, hostname, key):
        fingerprint = hashlib.sha256(
            key.asbytes()
        ).hexdigest()

        fingerprint = ":".join(
            fingerprint[i:i + 2]
            for i in range(0, len(fingerprint), 2)
        )

        self.worker.host_key_decision.clear()
        self.worker.host_key_request.emit(
            hostname, fingerprint
        )

        if not self.worker.host_key_decision.wait(120):
            raise paramiko.SSHException(
                "Host key confirmation timed out"
            )

        if not self.worker.host_key_accepted:
            raise paramiko.SSHException(
                "Host key rejected"
            )

        client.get_host_keys().add(
            hostname, key.get_name(), key
        )


class SSHWorker(QThread):
    output = pyqtSignal(str)
    connected = pyqtSignal()
    disconnected = pyqtSignal()
    error = pyqtSignal(str)
    host_key_request = pyqtSignal(str, str)

    def __init__(self, host, port, username, password):
        super().__init__()

        self.host = host
        self.port = port
        self.username = username
        self.password = password

        self.client = None
        self.channel = None

        self.running = True
        self.commands = queue.Queue()

        self.host_key_decision = threading.Event()
        self.host_key_accepted = False

    def send_command(self, command):
        self.commands.put(command)

    def stop(self):
        self.running = False

        self.host_key_accepted = False
        self.host_key_decision.set()

        if self.channel:
            self.channel.close()

        if self.client:
            self.client.close()

    def run(self):
        try:
            self.client = paramiko.SSHClient()

            if os.path.exists(KNOWN_HOSTS):
                self.client.load_host_keys(KNOWN_HOSTS)

            self.client.set_missing_host_key_policy(
                HostKeyPolicy(self)
            )

            self.client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=10,
                banner_timeout=15,
                auth_timeout=15,
                allow_agent=False,
                look_for_keys=False
            )

            if not self.running:
                return

            self.client.save_host_keys(KNOWN_HOSTS)

            self.channel = self.client.invoke_shell(
                term="xterm",
                width=120,
                height=35
            )

            self.channel.settimeout(0.2)

            self.connected.emit()
            self.output.emit(
                "\r\n[DaviSSH] Connected to "
                + self.host + "\r\n"
            )

            while self.running:
                while not self.commands.empty():
                    command = self.commands.get_nowait()

                    if self.channel and not self.channel.closed:
                        self.channel.send(command)

                try:
                    if self.channel.recv_ready():
                        data = self.channel.recv(4096)

                        if not data:
                            break

                        self.output.emit(
                            data.decode("utf-8", errors="replace")
                        )

                except Exception:
                    if not self.running:
                        break
                    raise

                self.msleep(30)

        except Exception as e:
            if self.running:
                self.error.emit(str(e))

        finally:
            if self.client:
                self.client.close()

            self.disconnected.emit()


class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("DaviSSH")
        self.resize(1100, 700)

        self.worker = None
        self.servers = []

        self.load_servers()
        self.build_ui()

    def build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)

        main = QHBoxLayout(root)
        main.setContentsMargins(0, 0, 0, 0)
        main.setSpacing(0)

        sidebar = QFrame()
        sidebar.setFixedWidth(250)
        sidebar.setObjectName("sidebar")

        side = QVBoxLayout(sidebar)
        side.setContentsMargins(15, 20, 15, 15)

        logo = QLabel("DaviSSH")
        logo.setObjectName("logo")

        side.addWidget(logo)
        side.addWidget(QLabel("SSH CLIENT"))

        side.addSpacing(20)
        side.addWidget(QLabel("SAVED SERVERS"))

        self.server_list = QListWidget()
        self.server_list.itemDoubleClicked.connect(
            self.select_server
        )

        side.addWidget(self.server_list)

        add_server = QPushButton("+ Add server")
        add_server.clicked.connect(self.add_server)
        side.addWidget(add_server)

        main.addWidget(sidebar)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(25, 20, 25, 20)

        header = QHBoxLayout()

        title = QLabel("Terminal")
        title.setObjectName("title")

        self.status = QLabel("● Disconnected")
        self.status.setObjectName("status")

        header.addWidget(title)
        header.addStretch()
        header.addWidget(self.status)

        layout.addLayout(header)

        connection = QHBoxLayout()

        self.host = QLineEdit()
        self.host.setPlaceholderText("Server IP / hostname")

        self.port = QLineEdit("22")
        self.port.setFixedWidth(70)

        self.username = QLineEdit()
        self.username.setPlaceholderText("Username")

        self.password = QLineEdit()
        self.password.setPlaceholderText("Password")
        self.password.setEchoMode(
            QLineEdit.Password
        )

        connection.addWidget(self.host)
        connection.addWidget(self.port)
        connection.addWidget(self.username)
        connection.addWidget(self.password)

        layout.addLayout(connection)

        buttons = QHBoxLayout()

        self.connect_btn = QPushButton("Connect")
        self.connect_btn.clicked.connect(self.connect_ssh)

        self.disconnect_btn = QPushButton("Disconnect")
        self.disconnect_btn.clicked.connect(
            self.disconnect_ssh
        )
        self.disconnect_btn.setEnabled(False)

        buttons.addWidget(self.connect_btn)
        buttons.addWidget(self.disconnect_btn)

        layout.addLayout(buttons)

        self.terminal = QPlainTextEdit()
        self.terminal.setReadOnly(True)
        self.terminal.setObjectName("terminal")

        layout.addWidget(self.terminal, 1)

        command_row = QHBoxLayout()

        self.command = QLineEdit()
        self.command.setPlaceholderText(
            "Enter command..."
        )

        self.command.returnPressed.connect(
            self.send_command
        )

        send = QPushButton("Send")
        send.clicked.connect(self.send_command)

        command_row.addWidget(self.command)
        command_row.addWidget(send)

        layout.addLayout(command_row)

        main.addWidget(content)

        self.setStyleSheet("""
            QWidget {
                background: #0b0e0d;
                color: #e8f5ed;
                font-family: Segoe UI;
                font-size: 13px;
            }

            #sidebar {
                background: #111714;
                border-right: 1px solid #26352d;
            }

            #logo {
                color: #00e676;
                font-size: 27px;
                font-weight: bold;
            }

            #title {
                font-size: 24px;
                font-weight: bold;
            }

            #status {
                color: #ff6969;
            }

            QLineEdit {
                background: #151a18;
                border: 1px solid #293b31;
                border-radius: 7px;
                padding: 11px;
                color: white;
            }

            QLineEdit:focus {
                border: 1px solid #00e676;
            }

            QPushButton {
                background: #173b29;
                border: 1px solid #226c42;
                border-radius: 7px;
                padding: 11px 18px;
                color: white;
                font-weight: bold;
            }

            QPushButton:hover {
                background: #20583a;
            }

            QPushButton:disabled {
                background: #242a26;
                color: #777;
            }

            #terminal {
                background: #050806;
                border: 1px solid #26352d;
                border-radius: 9px;
                color: #00e676;
                font-family: Consolas;
                font-size: 13px;
                padding: 12px;
            }

            QListWidget {
                background: #111714;
                border: none;
                outline: none;
            }

            QListWidget::item {
                padding: 12px;
                border-radius: 6px;
            }

            QListWidget::item:selected {
                background: #173b29;
                color: #00e676;
            }
        """)

        self.refresh_servers()

    def connect_ssh(self):
        if self.worker and self.worker.isRunning():
            return

        host = self.host.text().strip()
        username = self.username.text().strip()
        password = self.password.text()

        try:
            port = int(self.port.text())
            if not 1 <= port <= 65535:
                raise ValueError()
        except ValueError:
            QMessageBox.warning(
                self, "DaviSSH", "Invalid port."
            )
            return

        if not host or not username:
            QMessageBox.warning(
                self, "DaviSSH",
                "Enter host and username."
            )
            return

        self.terminal.clear()
        self.terminal.appendPlainText(
            "[DaviSSH] Connecting..."
        )

        self.worker = SSHWorker(
            host, port, username, password
        )

        self.worker.output.connect(
            self.terminal.insertPlainText
        )

        self.worker.connected.connect(
            self.on_connected
        )

        self.worker.disconnected.connect(
            self.on_disconnected
        )

        self.worker.error.connect(
            self.on_error
        )

        self.worker.host_key_request.connect(
            self.confirm_host_key
        )

        self.worker.start()

    def confirm_host_key(self, hostname, fingerprint):
        result = QMessageBox.question(
            self,
            "Verify SSH server",
            "This server has not been trusted before.\n\n"
            "Host: " + hostname +
            "\nSHA256 fingerprint:\n" + fingerprint +
            "\n\nOnly accept if you have verified "
            "this fingerprint with your server administrator.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if self.worker:
            self.worker.host_key_accepted = (
                result == QMessageBox.Yes
            )
            self.worker.host_key_decision.set()

    def on_connected(self):
        self.status.setText("● Connected")
        self.status.setStyleSheet("color: #00e676;")

        self.connect_btn.setEnabled(False)
        self.disconnect_btn.setEnabled(True)

    def on_disconnected(self):
        self.status.setText("● Disconnected")
        self.status.setStyleSheet("color: #ff6969;")

        self.connect_btn.setEnabled(True)
        self.disconnect_btn.setEnabled(False)

    def on_error(self, message):
        self.terminal.appendPlainText(
            "\n[ERROR] " + message
        )

    def disconnect_ssh(self):
        if self.worker:
            self.worker.stop()

        self.terminal.appendPlainText(
            "\n[DaviSSH] Disconnected."
        )

    def send_command(self):
        command = self.command.text()

        if not command.strip():
            return

        if not self.worker or not self.worker.isRunning():
            self.terminal.appendPlainText(
                "[ERROR] Not connected."
            )
            return

        self.worker.send_command(command + "\n")
        self.command.clear()

    def add_server(self):
        host, ok = QInputDialog.getText(
            self, "Add server", "Server IP / hostname:"
        )

        if not ok or not host.strip():
            return

        username, ok = QInputDialog.getText(
            self, "Add server", "Username:"
        )

        if not ok or not username.strip():
            return

        self.servers.append({
            "host": host.strip(),
            "port": 22,
            "username": username.strip()
        })

        self.save_servers()
        self.refresh_servers()

    def refresh_servers(self):
        self.server_list.clear()

        for server in self.servers:
            self.server_list.addItem(
                server["username"] + "@" + server["host"]
            )

    def select_server(self, item):
        index = self.server_list.row(item)
        server = self.servers[index]

        self.host.setText(server["host"])
        self.port.setText(str(server["port"]))
        self.username.setText(server["username"])

    def load_servers(self):
        try:
            with open(SERVERS_FILE, "r") as f:
                self.servers = json.load(f)
        except Exception:
            self.servers = []

    def save_servers(self):
        with open(SERVERS_FILE, "w") as f:
            json.dump(
                self.servers, f, indent=4
            )

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(2000)

        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = MainWindow()
    window.show()

    sys.exit(app.exec_())
