"""Beginner entry point; routes to existing, authorized workflows."""
import tkinter as tk
from tkinter import ttk
from .readiness import Readiness, inventory
from .runtime_health import diagnostics
from .orchestration import for_app
from .ui_lifecycle import watch_poll
from queue import Queue, Empty
from threading import Event


class GuidedWindow(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app, name='guided_assessment')
        self.title('Sentinel | New assessment')
        self.geometry('720x620')
        self.minsize(580, 520)
        self.app = app
        self.orchestrator = for_app(app)
        self.health_queue = Queue()
        self.health_cancel = Event()
        self.health_busy = False
        watch_poll(self)
        self.bind('<Destroy>', self.on_destroy, add='+')
        body = ttk.Frame(self, padding=18)
        body.pack(fill='both', expand=True)
        ttk.Label(body, text='What would you like to secure?',
                  style='Title.TLabel').pack(anchor='w', pady=(0, 8))
        choices = (
            ('Website: quick security check',
             'Check HTTPS, headers and cookies on one authorized URL.',
             self.website),
            ('Website or network: security tools',
             'Choose an existing tool and review its scope, profile and execution environment.',
             self.tools),
            ('Software dependencies',
             'Review a local dependency inventory against supplied advisory data.',
             self.dependencies),
        )
        for label, description, action in choices:
            row = ttk.Frame(body)
            row.pack(fill='x', pady=4)
            ttk.Button(row, text=label, command=action).pack(anchor='w')
            ttk.Label(row, text=description, wraplength=520).pack(anchor='w')
        ttk.Separator(body).pack(fill='x', pady=12)
        ttk.Label(body, text='Security engine inventory',
                  style='Title.TLabel').pack(anchor='w')
        ttk.Label(body, text='Detection is not readiness. Check engines to test the local runtime and prepared tool versions.',
                  wraplength=520).pack(anchor='w', pady=(2, 8))
        frame = ttk.Frame(body)
        frame.pack(fill='both', expand=True)
        self.tree = ttk.Treeview(frame, columns=('name', 'state'), show='headings', height=6)
        self.tree.heading('name', text='Engine / tool')
        self.tree.heading('state', text='Local status')
        self.tree.column('name', width=270)
        self.tree.column('state', width=150)
        scroll = ttk.Scrollbar(frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side='left', fill='both', expand=True)
        scroll.pack(side='right', fill='y')
        self.detail = tk.StringVar(value='')
        ttk.Label(body, textvariable=self.detail, wraplength=520).pack(anchor='w', pady=6)
        self.tree.bind('<<TreeviewSelect>>', self.selected)
        controls = ttk.Frame(body)
        controls.pack(fill='x')
        self.refresh_btn = ttk.Button(controls, text='Refresh inventory', command=self.refresh)
        self.refresh_btn.pack(side='left')
        self.check_btn = ttk.Button(controls, text='Check engines', command=self.check_engines)
        self.check_btn.pack(side='left', padx=6)
        self.cancel_btn = ttk.Button(controls, text='Cancel check', command=self.cancel_check, state='disabled')
        self.cancel_btn.pack(side='left')
        self.health_status = tk.StringVar(value='Checks may start a prepared WSL distribution or an isolated local Docker container.')
        ttk.Label(body, textvariable=self.health_status, wraplength=520).pack(anchor='w', pady=4)
        self.refresh()
        self.poll_timer = self.after(100, self.poll_health)

    def refresh(self):
        self.base_rows = inventory()
        self.show_rows(self.base_rows)
        self.health_status.set('Inventory refreshed. Engine checks are optional; WSL may start its distribution.')

    def show_rows(self, rows):
        self.rows = rows
        self.tree.delete(*self.tree.get_children())
        for i, row in enumerate(self.rows):
            self.tree.insert('', 'end', iid=str(i), values=(row.name, row.state))
        self.detail.set('Select a row for more information.')

    def check_engines(self):
        if self.health_busy:
            return
        self.health_cancel = Event()
        cancel = self.health_cancel
        queue = self.health_queue
        try:
            self.health_job = self.orchestrator.submit(
                lambda: diagnostics(cancel),
                lambda result, error: queue.put((result, error)), cancel)
        except RuntimeError as exc:
            self.health_status.set(str(exc))
            return
        self.health_busy = True
        self.refresh_btn.configure(state='disabled')
        self.check_btn.configure(state='disabled')
        self.cancel_btn.configure(state='normal')
        self.show_rows(self.base_rows)
        self.health_status.set('Engine check queued. No assessment target will be contacted.')

    def cancel_check(self):
        self.health_cancel.set()
        self.cancel_btn.configure(state='disabled')
        self.health_status.set('Cancelling engine check…')

    def poll_health(self):
        if self.health_busy:
            try:
                result, error = self.health_queue.get_nowait()
            except Empty:
                if not self.health_cancel.is_set():
                    self.health_status.set('Engine check: ' + self.health_job.state)
            else:
                self.health_busy = False
                self.refresh_btn.configure(state='normal')
                self.check_btn.configure(state='normal')
                self.cancel_btn.configure(state='disabled')
                if self.health_cancel.is_set():
                    self.health_status.set('Engine check cancelled; results discarded.')
                elif error or not result:
                    self.health_status.set(error or 'Engine check failed.')
                else:
                    self.show_rows(self.base_rows + tuple(Readiness(**row) for row in result['rows']))
                    self.health_status.set('Diagnostics finished. Scan compatibility and scope are not verified.')
        self.poll_timer = self.after(100, self.poll_health)

    def on_destroy(self, event):
        if event.widget is self:
            self.health_cancel.set()

    def selected(self, _event=None):
        selected = self.tree.selection()
        if selected:
            self.detail.set(self.rows[int(selected[0])].explanation)

    def website(self):
        # Return to the existing single-URL workflow; do not initiate a scan.
        self.app.auth.set(False)
        self.destroy()
        self.app.lift()

    def tools(self):
        self.destroy()
        self.app.open_network()

    def dependencies(self):
        self.destroy()
        self.app.open_dependencies()
