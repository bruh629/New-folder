import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QTextCharFormat, QFont
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from port_scanner import scan_ports
from cve_lookup import lookup_cve
from win_auditor import run_audit

# ─── Scanner Thread ───────────────────────────────────────
class ScannerThread(QThread):
    update = pyqtSignal(str, str)  # message, color
    finished = pyqtSignal()

    def __init__(self, target):
        super().__init__()
        self.target = target

    def ask_ollama(self, prompt):
        response = requests.post("http://localhost:11434/api/generate",
            json={
                "model": "llama3.1:8b",
                "prompt": prompt,
                "stream": False
            },
            timeout=120
        )
        return response.json()["response"]

    def run(self):
        self.update.emit(f"Starting scan on {self.target}...\n", "white")

        # Port Scan
        self.update.emit("\n[1/3] Running Port Scanner...\n", "cyan")
        ports = scan_ports(self.target)

        for port in ports:
            self.update.emit(f"\n--- Port {port['port']} ({port['service']}) ---\n", "yellow")

            prompt = f"""You are a cybersecurity expert. Analyze this open port and provide:
1. Severity (Critical/High/Medium/Low)
2. Risk in plain English
3. One specific fix

Port: {port['port']}
Service: {port['service']}
Version: {port['version']}
Protocol: {port['protocol']}"""

            analysis = self.ask_ollama(prompt)
            self.update.emit(analysis + "\n", "white")

            # CVE lookup
            if port['service']:
                cves = lookup_cve(port['service'], port['version'])
                for cve in cves[:2]:
                    self.update.emit(f"\n  CVE: {cve['id']} | Score: {cve['score']} | Severity: {cve['severity']}\n", "orange")

        # Windows Audit
        self.update.emit("\n[2/3] Running Windows Audit...\n", "cyan")
        audit_results = run_audit()

        for result in audit_results:
            if result['severity'] != "Safe":
                self.update.emit(f"\n⚠ {result['check']} — {result['detail']}\n", "red")
            else:
                self.update.emit(f"\n✅ {result['check']} — {result['detail']}\n", "green")

        self.update.emit("\n✅ Scan Complete!\n", "green")
        self.finished.emit()


# ─── Main Window ───────────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI Vulnerability Scanner")
        self.setGeometry(100, 100, 900, 700)
        self.setStyleSheet("background-color: #1e1e1e;")
        self.build_ui()

    def build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setSpacing(10)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title = QLabel("AI Vulnerability Scanner")
        title.setStyleSheet("color: #00ff99; font-size: 26px; font-weight: bold;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        # Input row
        input_row = QHBoxLayout()

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter target IP (e.g. 127.0.0.1)")
        self.target_input.setStyleSheet("""
            background-color: #2d2d2d;
            color: white;
            border: 1px solid #00ff99;
            border-radius: 5px;
            padding: 8px;
            font-size: 14px;
        """)
        input_row.addWidget(self.target_input)

        self.scan_button = QPushButton("Start Scan")
        self.scan_button.setStyleSheet("""
            background-color: #00ff99;
            color: #1e1e1e;
            border-radius: 5px;
            padding: 8px 20px;
            font-size: 14px;
            font-weight: bold;
        """)
        self.scan_button.clicked.connect(self.start_scan)
        input_row.addWidget(self.scan_button)

        layout.addLayout(input_row)

        # Results area
        self.results = QTextEdit()
        self.results.setReadOnly(True)
        self.results.setStyleSheet("""
            background-color: #0d0d0d;
            color: white;
            border: 1px solid #333;
            border-radius: 5px;
            padding: 10px;
            font-family: Consolas;
            font-size: 13px;
        """)
        layout.addWidget(self.results)

        # Status bar
        self.status = QLabel("Ready")
        self.status.setStyleSheet("color: #888; font-size: 12px;")
        layout.addWidget(self.status)

    def start_scan(self):
        target = self.target_input.text().strip()
        if not target:
            self.status.setText("Please enter a target IP")
            return

        self.results.clear()
        self.scan_button.setEnabled(False)
        self.status.setText("Scanning...")

        self.thread = ScannerThread(target)
        self.thread.update.connect(self.append_text)
        self.thread.finished.connect(self.scan_done)
        self.thread.start()

    def append_text(self, text, color):
        self.results.setTextColor(QColor(color))
        self.results.insertPlainText(text)
        self.results.verticalScrollBar().setValue(
            self.results.verticalScrollBar().maximum()
        )

    def scan_done(self):
        self.scan_button.setEnabled(True)
        self.status.setText("Scan complete")


# ─── Run ───────────────────────────────────────────────────
app = QApplication(sys.argv)
window = MainWindow()
window.show()
sys.exit(app.exec())