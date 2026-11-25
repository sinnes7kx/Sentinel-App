"""User-approved installation and preparation workspace for Windows."""
import tkinter as tk
from tkinter import ttk, messagebox
from queue import Queue, Empty
from threading import Event
from .orchestration import for_app
from .ui_lifecycle import watch_poll, bind_escape
from .tool_setup import setup


class ToolSetupWindow(tk.Toplevel):
    def __init__(self, tools):
        super().__init__(tools, name='tool_setup')
        self.tools = tools
        self.title('Sentinel | Automatic tool setup')
        self.geometry('650x430')
        self.minsize(560, 380)
        self.orchestrator = for_app(tools.app)
        self.queue = Queue()
        self.cancel = Event()
        self.busy = False
        self.status = tk.StringVar(value='Choose what Sentinel should prepare.')
        self.choice = tk.StringVar(value='nmap' if tools.tool.id == 'nmap' else 'toolkit')
        watch_poll(self)
        bind_escape(self, self.close)
        self.protocol('WM_DELETE_WINDOW', self.close)
        body = ttk.Frame(self, padding=18)
        body.pack(fill='both', expand=True)
        ttk.Label(body, text='Prepare security tools', style='Title.TLabel').pack(anchor='w')
        ttk.Label(body, text='Sentinel detects existing components and downloads missing ones. No VirtualBox or separate Kali installation is required.',
                  wraplength=565).pack(anchor='w', pady=(6, 12))
        self.options = []
        for label, value in (('Nmap — native Windows', 'nmap'),
                             ('Docker Desktop — Linux runtime', 'docker'),
                             ('Kali toolkit — WhatWeb and sslscan via Docker', 'toolkit')):
            radio = ttk.Radiobutton(body, text=label, value=value, variable=self.choice)
            radio.pack(anchor='w', pady=4)
            self.options.append(radio)
        ttk.Label(body, text='Internet access may be needed. Windows, Npcap and Docker may show administrator, license or restart prompts. Sentinel will not accept terms for you.',
                  style='Muted.TLabel', wraplength=565).pack(anchor='w', pady=12)
        self.button = ttk.Button(body, text='Detect and install missing components',
                                 style='Primary.TButton', command=self.start)
        self.button.pack(anchor='w')
        ttk.Label(body, textvariable=self.status, wraplength=565).pack(anchor='w', pady=10)
        self.poll_timer = self.after(100, self.poll)

    def start(self):
        if self.busy:
            return
        kind = self.choice.get()
        if not messagebox.askokcancel('Prepare tools',
                'Allow Sentinel to detect and download the selected components if needed? Vendor installers may open. No assessment will start.',
                parent=self):
            return
        self.cancel = Event()
        cancel, queue = self.cancel, self.queue
        def operation():
            try:
                return setup(kind, cancel)
            except ValueError as exc:
                return {'status': 'failed', 'message': str(exc)}
        try:
            self.orchestrator.submit(operation, lambda result, error: queue.put((result, error)), cancel)
        except RuntimeError as exc:
            self.status.set(str(exc))
            return
        self.busy = True
        self.button.state(['disabled'])
        for radio in self.options:
            radio.state(['disabled'])
        self.status.set('Preparing selected components. Complete any vendor prompts that appear.')

    def poll(self):
        try:
            result, error = self.queue.get_nowait()
        except Empty:
            pass
        else:
            self.busy = False
            self.button.state(['!disabled'])
            for radio in self.options:
                radio.state(['!disabled'])
            self.status.set(error or result.get('error') or result['message'])
            if not error and result.get('status') == 'completed':
                if result.get('backend') == 'docker' and not self.tools.busy and not self.tools.wsl_busy and self.tools.tool.id in ('whatweb', 'sslscan'):
                    self.tools.backend.set('docker')
                    self.tools.environment.set(result['environment'])
                self.tools.update_tool_info()
        self.poll_timer = self.after(100, self.poll)

    def close(self):
        if self.busy:
            self.status.set('Complete the current installer prompts first. Closing Sentinel does not undo installation.')
            return
        self.destroy()
