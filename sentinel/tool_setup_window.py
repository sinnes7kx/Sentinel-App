"""User-approved installation and preparation workspace for Windows."""
import tkinter as tk
from tkinter import ttk, messagebox
from queue import Queue, Empty
from threading import Event
from .orchestration import for_app
from .ui_lifecycle import watch_poll, bind_escape
from .verified_setup import prepare_verified
from .tool_inventory import snapshot
from .desktop_theme import scrollable
from .setup_recovery import recovery
from .tool_selfcheck import check_installation, check_zap_installation


class ToolSetupWindow(tk.Toplevel):
    def __init__(self, tools):
        super().__init__(tools, name='tool_setup')
        self.tools = tools
        self.title('Sentinel | Tool control center')
        self.geometry('800x560')
        self.minsize(740, 500)
        self.orchestrator = for_app(tools.app)
        self.queue = Queue()
        self.cancel = Event()
        self.busy = False
        self.mode = None
        self.rows = []
        self.last_setup_kind = None
        self.last_retry_allowed = False
        self.status = tk.StringVar(value='Choose what Sentinel should prepare.')
        self.choice = tk.StringVar(value='all')
        watch_poll(self)
        bind_escape(self, self.close)
        self.protocol('WM_DELETE_WINDOW', self.close)
        body = ttk.Frame(self, padding=10)
        body.pack(fill='both', expand=True)
        ttk.Label(body, text='Tool control center', style='Title.TLabel').pack(anchor='w')
        self.pages = ttk.Notebook(body)
        self.pages.pack(fill='both', expand=True)
        self.pages.enable_traversal()
        inventory_page = self.inventory_page = ttk.Frame(self.pages, padding=8)
        install_page = self.install_page = ttk.Frame(self.pages, padding=8)
        self.pages.add(inventory_page, text='Tool status')
        self.pages.add(install_page, text='Install / update')
        ttk.Label(inventory_page, text='Local inventory • Detection is not proof that a scan will work.',
                  style='Muted.TLabel').pack(anchor='w', pady=(3, 8))
        table = ttk.Frame(inventory_page)
        table.pack(fill='both', expand=True)
        self.tree = ttk.Treeview(table, columns=('name', 'state'), show='headings', height=7)
        self.tree.heading('name', text='Component')
        self.tree.heading('state', text='Local status')
        self.tree.column('name', width=300)
        self.tree.column('state', width=150)
        scrollable(table, self.tree)
        self.tree.bind('<<TreeviewSelect>>', self.selected)
        self.detail = tk.StringVar(value='Refresh to inspect the local environment.')
        ttk.Label(inventory_page, textvariable=self.detail, wraplength=680, justify='left',
                  style='Muted.TLabel').pack(side='bottom', fill='x', pady=4, before=table)
        controls = ttk.Frame(inventory_page)
        controls.pack(side='bottom', fill='x', before=table)
        self.refresh_button = ttk.Button(controls, text='Refresh status', command=self.refresh)
        self.refresh_button.pack(side='left')
        self.test_button = ttk.Button(controls, text='Test toolkit', command=self.test_installation)
        self.test_button.pack(side='left', padx=6)
        self.zap_test_button = ttk.Button(controls, text='Test ZAP', command=self.test_zap)
        self.zap_test_button.pack(side='left')
        self.selected_button = ttk.Button(controls, text='Prepare selected', command=self.prepare_selected, state='disabled')
        self.selected_button.pack(side='left', padx=6)
        self.cancel_button = ttk.Button(controls, text='Cancel check', command=self.cancel_refresh, state='disabled')
        self.cancel_button.pack(side='left')
        ttk.Label(install_page, text='Prepare missing components. No separate Kali installation is required.',
                  wraplength=680).pack(anchor='w', pady=(0, 5))
        self.options = []
        choices = ttk.Frame(install_page)
        choices.pack(fill='x')
        for i, (label, value) in enumerate((('Recommended: Nmap + toolkit', 'all'),
                             ('Nmap for Windows', 'nmap'),
                             ('Docker Desktop', 'docker'),
                             ('Toolkit: WhatWeb + sslscan', 'toolkit'),
                             ('ZAP (larger download)', 'zap'),
                             ('Check for ZAP updates', 'zap-update'))):
            radio = ttk.Radiobutton(choices, text=label, value=value, variable=self.choice)
            radio.grid(row=i // 2, column=i % 2, sticky='w', padx=(0, 12), pady=2)
            self.options.append(radio)
        ttk.Label(install_page, text='Internet access may be needed. Windows, Npcap and Docker may show administrator, license or restart prompts. Sentinel will not accept terms for you.',
                  style='Muted.TLabel', wraplength=680).pack(anchor='w', pady=5)
        self.button = ttk.Button(install_page, text='Detect and install missing components',
                                 style='Primary.TButton', command=self.start)
        self.button.pack(anchor='w')
        ttk.Label(body, textvariable=self.status, wraplength=680, justify='left').pack(side='bottom', fill='x', pady=(4, 0), before=self.pages)
        self.recovery_title = tk.StringVar(value='')
        self.recovery_text = tk.StringVar(value='')
        ttk.Label(install_page, textvariable=self.recovery_title, style='Title.TLabel').pack(anchor='w')
        ttk.Label(install_page, textvariable=self.recovery_text, wraplength=680, justify='left',
                  style='Muted.TLabel').pack(anchor='w', pady=(2, 4))
        self.retry_button = ttk.Button(install_page, text='Try again', command=self.retry_setup, state='disabled')
        self.retry_button.pack(anchor='w')
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

    def test_installation(self):
        self.start_selfcheck('selfcheck', check_installation, 'Testing the saved Docker toolkit offline. No target is contacted.')

    def test_zap(self):
        self.start_selfcheck('zapcheck', check_zap_installation, 'Testing installed ZAP offline. No downloads or targets.')

    def start_selfcheck(self, mode, operation, message):
        if self.busy:
            return
        self.cancel = Event()
        cancel, queue = self.cancel, self.queue
        try:
            self.orchestrator.submit(lambda: operation(cancel),
                                     lambda result, error: queue.put((result, error)), cancel)
        except RuntimeError as exc:
            self.status.set(str(exc))
            return
        self.mode = mode
        self.set_busy(True)
        self.status.set(message)

    def cancel_refresh(self):
        if self.busy and self.mode in ('inventory', 'selfcheck', 'zapcheck'):
            self.cancel.set()

    def set_busy(self, busy):
        self.busy = busy
        for widget in [self.button, self.refresh_button, self.test_button, self.zap_test_button, *self.options]:
            widget.state(['disabled'] if busy else ['!disabled'])
        self.cancel_button.configure(state='normal' if busy and self.mode in ('inventory', 'selfcheck', 'zapcheck') else 'disabled')
        self.retry_button.state(['!disabled'] if not busy and self.last_retry_allowed else ['disabled'])
        self.selected()

    def retry_setup(self):
        if not self.busy and self.last_setup_kind:
            self.choice.set(self.last_setup_kind)
            self.start()

    def start(self):
        if self.busy:
            return
        kind = self.choice.get()
        prompt = ('Check the official ZAP stable image for updates? This may download a large image and install Docker if missing. No assessment will start.'
                  if kind == 'zap-update' else
                  'Allow Sentinel to detect and download the selected components if needed? Vendor installers may open. No assessment will start.')
        if not messagebox.askokcancel('Prepare tools', prompt, parent=self):
            return
        self.cancel = Event()
        cancel, queue = self.cancel, self.queue
        def operation():
            try:
                return prepare_verified(kind, cancel)
            except ValueError as exc:
                return {'status': 'failed', 'message': str(exc)}
        try:
            self.orchestrator.submit(operation, lambda result, error: queue.put((result, error)), cancel)
        except RuntimeError as exc:
            self.status.set(str(exc))
            return
        self.pages.select(self.install_page)
        self.last_setup_kind = kind
        self.last_retry_allowed = False
        self.mode = 'setup'
        self.recovery_title.set('')
        self.recovery_text.set('')
        self.retry_button.state(['disabled'])
        self.set_busy(True)
        self.status.set('Preparing and verifying selected components. Complete any vendor prompts that appear.')

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
            elif mode in ('selfcheck', 'zapcheck'):
                names = ('whatweb', 'sslscan') if mode == 'selfcheck' else ('ZAP (offline test)',)
                self.rows = [row for row in self.rows if row['name'] not in names]
                if result and not error:
                    self.rows.extend(result.get('rows', []))
                self.tree.delete(*self.tree.get_children())
                for i, row in enumerate(self.rows):
                    self.tree.insert('', 'end', iid=str(i), values=(row['name'], row['state']))
                self.selected()
                self.status.set(error or (result or {}).get('message', 'Installation test could not finish.'))
            else:
                outcome = result or {'status': 'failed'}
                self.status.set(error or outcome.get('error') or outcome.get('message', 'Setup could not finish.'))
                advice = recovery(outcome)
                self.recovery_title.set(advice.heading)
                self.recovery_text.set(advice.instruction)
                self.last_retry_allowed = advice.retry
                self.retry_button.state(['!disabled'] if advice.retry else ['disabled'])
            if mode == 'setup' and not error and result and 'verification' in result:
                self.rows = [row for row in self.rows if row['name'] not in ('whatweb', 'sslscan')]
                self.rows.extend(result['verification'].get('rows', []))
                self.tree.delete(*self.tree.get_children())
                for i, row in enumerate(self.rows):
                    self.tree.insert('', 'end', iid=str(i), values=(row['name'], row['state']))
                self.selected()
                if result.get('status') == 'completed':
                    self.pages.select(self.inventory_page)
            if mode == 'setup' and not error and result and result.get('status') == 'completed':
                if result.get('backend') == 'docker' and not self.tools.busy and not self.tools.wsl_busy and self.tools.tool.id in ('whatweb', 'sslscan'):
                    self.tools.backend.set('docker')
                    self.tools.environment.set(result['environment'])
                self.tools.update_tool_info()
                self.detail.set('Setup completed. Offline tool versions checked; scan connectivity is not verified.'
                                if result.get('verification') else 'Setup completed. Refresh status to inspect the updated inventory.')
        self.poll_timer = self.after(100, self.poll)

    def close(self):
        if self.busy and self.mode in ('selfcheck', 'zapcheck'):
            self.cancel.set()
            self.status.set('Cancelling test and checking container cleanup. Close when finished.')
            return
        if self.busy and self.mode == 'inventory':
            self.cancel.set()
            self.destroy()
            return
        if self.busy:
            self.status.set('Complete the current installer prompts first. Closing Sentinel does not undo installation.')
            return
        self.destroy()
