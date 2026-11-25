"""Beginner entry point; routes to existing, authorized workflows."""
import tkinter as tk
from tkinter import ttk
from .readiness import inventory


class GuidedWindow(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app, name='guided_assessment')
        self.title('Sentinel | New assessment')
        self.geometry('720x620')
        self.minsize(580, 520)
        self.app = app
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
        ttk.Label(body, text='Local detection only. Detected does not mean tested or ready.',
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
        ttk.Button(body, text='Refresh local inventory', command=self.refresh).pack(anchor='w')
        self.refresh()

    def refresh(self):
        self.rows = inventory()
        self.tree.delete(*self.tree.get_children())
        for i, row in enumerate(self.rows):
            self.tree.insert('', 'end', iid=str(i), values=(row.name, row.state))
        self.detail.set('Select a row for more information.')

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
