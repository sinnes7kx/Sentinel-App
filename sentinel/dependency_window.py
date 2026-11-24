"""Beginner interface for offline dependency advisory assessment."""
import json
from pathlib import Path
from queue import Queue, Empty
from threading import Thread
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from .dependencies import assess


class DependencyWindow(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app)
        self.title('Sentinel | Local dependency check')
        self.geometry('880x650')
        self.queue = Queue()
        self.busy = False
        self.result = None
        self.inventory = tk.StringVar()
        self.feed = tk.StringVar()
        self.format = tk.StringVar(value='requirements')
        self.status = tk.StringVar(value='Your files stay on this computer. No packages are installed or executed.')
        body = ttk.Frame(self, padding=20)
        body.pack(fill='both', expand=True)
        ttk.Label(body, text='Are my Python dependencies affected?', font=('Segoe UI', 16, 'bold')).pack(anchor='w')
        ttk.Label(body, text='Compare a package inventory with advisory files you trust. Missing or unsupported information stays unknown.', wraplength=800).pack(anchor='w', pady=8)
        for label, variable in [('1. Choose your package inventory', self.inventory), ('2. Choose a local OSV advisory JSON array', self.feed)]:
            ttk.Label(body, text=label).pack(anchor='w')
            row = ttk.Frame(body)
            row.pack(fill='x', pady=5)
            ttk.Entry(row, textvariable=variable).pack(side='left', fill='x', expand=True)
            ttk.Button(row, text='Browse…', command=lambda v=variable: self.choose(v)).pack(side='right', padx=8)
        row = ttk.Frame(body)
        row.pack(fill='x')
        for text, value in [('Requirements file', 'requirements'), ('pip inspect JSON inventory', 'pip-inspect')]:
            ttk.Radiobutton(row, text=text, variable=self.format, value=value).pack(side='left', padx=6)
        row = ttk.Frame(body)
        row.pack(fill='x', pady=12)
        self.button = ttk.Button(row, text='3. Check these files', command=self.start)
        self.button.pack(side='left')
        ttk.Button(row, text='Export result JSON', command=self.export).pack(side='left', padx=8)
        ttk.Label(body, textvariable=self.status, wraplength=800).pack(anchor='w', pady=5)
        self.tree = ttk.Treeview(body, columns=('package', 'version', 'result'), show='headings', height=8)
        for column, label in [('package', 'Package'), ('version', 'Version'), ('result', 'Result')]:
            self.tree.heading(column, text=label)
        self.tree.pack(fill='both', expand=True)
        self.tree.bind('<<TreeviewSelect>>', self.selected)
        self.detail = tk.Text(body, height=9, wrap='word')
        self.detail.pack(fill='both', expand=True, pady=8)
        self.say('Affected: an advisory matches this version.\nNo match in supplied feed: only these records were checked.\nUnknown: more information is needed.\n\nA result is not proof of exploitability or overall safety. Feed freshness is not verified.')
        self.after(100, self.poll)

    def choose(self, variable):
        path = filedialog.askopenfilename(parent=self)
        if path:
            variable.set(path)

    def say(self, text):
        self.detail.configure(state='normal')
        self.detail.delete('1.0', 'end')
        self.detail.insert('1.0', text)
        self.detail.configure(state='disabled')

    def start(self):
        if self.busy:
            return
        inventory, feed, format = self.inventory.get(), self.feed.get(), self.format.get()
        if not inventory or not feed:
            messagebox.showinfo('Choose files', 'Choose both your inventory and advisory file.', parent=self)
            return
        self.busy = True
        self.result = None
        self.tree.delete(*self.tree.get_children())
        self.button.configure(state='disabled')
        self.status.set('Reading local files…')
        def worker():
            try:
                self.queue.put((assess(inventory, feed, format), None))
            except RuntimeError as exc:
                self.queue.put((None, str(exc)))
            except Exception:
                self.queue.put((None, 'The files could not be assessed. Check their format, size and read permissions.'))
        Thread(target=worker, daemon=True).start()

    def poll(self):
        try:
            result, error = self.queue.get_nowait()
            self.busy = False
            self.button.configure(state='normal')
            self.result = result
            if error:
                self.status.set('Assessment could not complete.')
                self.say(error)
            else:
                summary = result['summary']
                self.status.set(f"{summary['affected']} affected • {summary['unknown']} unknown • {summary['unsupported_inventory_entries']} unsupported entries. Coverage remains partial.")
                for index, package in enumerate(result['packages']):
                    self.tree.insert('', 'end', iid=str(index), values=(package['name'], package['version'], package['status'].replace('_', ' ')))
                self.say('Select a package for evidence and next steps.\n\nUnsupported inventory entries:\n' + json.dumps(result['unsupported_inventory_entries'], indent=2))
        except Empty:
            pass
        self.after(100, self.poll)

    def selected(self, event=None):
        selection = self.tree.selection()
        if selection and self.result:
            package = self.result['packages'][int(selection[0])]
            self.say('WHAT WAS FOUND\n' + json.dumps(package['advisory_results'], indent=2) + '\n\nNEXT STEP\nReview matching advisories and their affected versions. Test a supported update in your project. No automatic fix or safe upgrade version is inferred. Unknown results need a complete, current advisory feed or supported inventory.')

    def export(self):
        if self.result is None:
            return
        path = filedialog.asksaveasfilename(parent=self, defaultextension='.json', initialfile='dependency-assessment.json')
        if path:
            try:
                Path(path).write_text(json.dumps(self.result, indent=2), encoding='utf-8')
            except OSError:
                messagebox.showerror('Export failed', 'Could not save to that location.', parent=self)
