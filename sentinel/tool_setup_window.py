"""User-approved installation and preparation workspace for Windows."""
import tkinter as tk
from tkinter import ttk, messagebox
from queue import Queue, Empty
from threading import Event
from .orchestration import for_app
from .ui_lifecycle import watch_poll, bind_escape
from .tool_setup import setup
from .tool_inventory import snapshot
from .desktop_theme import scrollable


class ToolSetupWindow(tk.Toplevel):
    def __init__(self, tools):
        super().__init__(tools, name='tool_setup')
        self.tools = tools
        self.title('Sentinel | Tool control center')
        self.geometry('820x700')
        self.minsize(640, 540)
        self.orchestrator = for_app(tools.app)
        self.queue = Queue()
        self.cancel = Event()
        self.busy = False
        self.mode = None
        self.rows = []
        self.status = tk.StringVar(value='Choose what Sentinel should prepare.')
        self.choice = tk.StringVar(value='all')
        watch_poll(self)
        bind_escape(self, self.close)
        self.protocol('WM_DELETE_WINDOW', self.close)
        body = ttk.Frame(self, padding=18)
        body.pack(fill='both', expand=True)
        ttk.Label(body, text='Tool control center', style='Title.TLabel').pack(anchor='w')
        ttk.Label(body, text='Local inventory • Detection is not proof that a scan will work.',
                  style='Muted.TLabel').pack(anchor='w', pady=(3, 8))
        table = ttk.Frame(body)
        table.pack(fill='both', expand=True)
        self.tree = ttk.Treeview(table, columns=('name', 'state'), show='headings', height=7)
        self.tree.heading('name', text='Component')
        self.tree.heading('state', text='Local status')
        self.tree.column('name', width=300)
        self.tree.column('state', width=150)
        scrollable(table, self.tree)
        self.tree.bind('<<TreeviewSelect>>', self.selected)
        self.detail = tk.StringVar(value='Refresh to inspect the local environment.')
        ttk.Label(body, textvariable=self.detail, wraplength=740, justify='left',
                  style='Muted.TLabel').pack(anchor='w', pady=6)
        controls = ttk.Frame(body)
        controls.pack(fill='x')
        self.refresh_button = ttk.Button(controls, text='Refresh status', command=self.refresh)
        self.refresh_button.pack(side='left')
        self.selected_button = ttk.Button(controls, text='Prepare selected', command=self.prepare_selected, state='disabled')
        self.selected_button.pack(side='left', padx=6)
        self.cancel_button = ttk.Button(controls, text='Cancel status check', command=self.cancel_refresh, state='disabled')
        self.cancel_button.pack(side='left')
        ttk.Separator(body).pack(fill='x', pady=10)
        ttk.Label(body, text='Sentinel detects existing components and downloads missing ones. No VirtualBox or separate Kali installation is required.',
                  wraplength=565).pack(anchor='w', pady=(6, 12))
        self.options = []
        for label, value in (('Recommended — Nmap and Kali toolkit', 'all'),
                             ('Nmap — native Windows', 'nmap'),
                             ('Docker Desktop — Linux runtime', 'docker'),
                             ('Kali toolkit — WhatWeb and sslscan via Docker', 'toolkit'),
                             ('ZAP — optional web security engine (larger download)', 'zap')):
            radio = ttk.Radiobutton(body, text=label, value=value, variable=self.choice)
            radio.pack(anchor='w', pady=4)
            self.options.append(radio)
        ttk.Label(body, text='Internet access may be needed. Windows, Npcap and Docker may show administrator, license or restart prompts. Sentinel will not accept terms for you.',
                  style='Muted.TLabel', wraplength=565).pack(anchor='w', pady=12)
        self.button = ttk.Button(body, text='Detect and install missing components',
                                 style='Primary.TButton', command=self.start)
        self.button.pack(anchor='w')
        ttk.Label(body, textvariable=self.status, wraplength=595, justify='left').pack(anchor='w', pady=10)
        self.poll_timer = self.after(100, self.poll)
        self.refresh()

    def selected(self, _event=None):
        ids = self.tree.selection()
        row = self.rows[int(ids[0])] if ids and int(ids[0]) < len(self.rows) else None
        self.detail.set(row['detail'] if row else 'Select a component for details.')
        self.selected_button.configure(state='normal' if row and row['action'] and not self.busy else 'disabled')

    def prepare_selected(self):
        ids = self.tree.selection()
        if self.busy or not ids:
            return
        action = self.rows[int(ids[0])]['action']
        if action:
            self.choice.set(action)
            self.start()

    def refresh(self):
        if self.busy:
            return
        self.cancel = Event()
        cancel, queue = self.cancel, self.queue
        try:
            self.orchestrator.submit(lambda: snapshot(cancel),
                                     lambda result, error: queue.put((result, error)), cancel)
        except RuntimeError as exc:
            self.status.set(str(exc))
            return
        self.mode = 'inventory'
        self.set_busy(True)
        self.status.set('Checking local metadata and Docker daemon. No downloads or scans.')

    def cancel_refresh(self):
        if self.busy and self.mode == 'inventory':
            self.cancel.set()

    def set_busy(self, busy):
        self.busy = busy
        for widget in [self.button, self.refresh_button, *self.options]:
            widget.state(['disabled'] if busy else ['!disabled'])
        self.cancel_button.configure(state='normal' if busy and self.mode == 'inventory' else 'disabled')
        self.selected()

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
        self.mode = 'setup'
        self.set_busy(True)
        self.status.set('Preparing selected components. Complete any vendor prompts that appear.')

    def poll(self):
        try:
            result, error = self.queue.get_nowait()
        except Empty:
            pass
        else:
            mode = self.mode
            self.mode = None
            self.set_busy(False)
            if mode == 'inventory':
                if not error and result and result.get('status') == 'completed':
                    self.rows = result['rows']
                    self.tree.delete(*self.tree.get_children())
                    for i, row in enumerate(self.rows):
                        self.tree.insert('', 'end', iid=str(i), values=(row['name'], row['state']))
                    self.selected()
                    self.status.set('Local status refreshed. No assessment was performed.')
                else:
                    self.status.set(error or 'Status check cancelled or incomplete. Previous inventory may be stale.')
            else:
                self.status.set(error or result.get('error') or result['message'])
            if mode == 'setup' and not error and result.get('status') == 'completed':
                if result.get('backend') == 'docker' and not self.tools.busy and not self.tools.wsl_busy and self.tools.tool.id in ('whatweb', 'sslscan'):
                    self.tools.backend.set('docker')
                    self.tools.environment.set(result['environment'])
                self.tools.update_tool_info()
                self.detail.set('Setup completed. Refresh status to inspect the updated inventory.')
        self.poll_timer = self.after(100, self.poll)

    def close(self):
        if self.busy and self.mode == 'inventory':
            self.cancel.set()
            self.destroy()
            return
        if self.busy:
            self.status.set('Complete the current installer prompts first. Closing Sentinel does not undo installation.')
            return
        self.destroy()
