"""Compact local advisory matching window."""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from threading import Event
from queue import Queue, Empty
from .desktop_theme import detail_box, scrollable
from .ui_lifecycle import watch_poll, bind_escape
from .cve_review import assess, identify
from .help_examples import cve_example
from .orchestration import for_app


class CVEWindow(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app, name='cve_review')
        self.app = app
        self.title('Sentinel | CVE review')
        self.geometry('760x560')
        self.minsize(660, 420)
        self.queue = Queue()
        self.cancel = Event()
        self.busy = False
        self.orchestrator = for_app(app)
        watch_poll(self)
        bind_escape(self)
        self.bind('<Destroy>', lambda e: self.cancel.set() if e.widget is self else None, add='+')
        self.vendor, self.product, self.version, self.feed = (tk.StringVar() for _ in range(4))
        self.status = tk.StringVar(value='No target contact. Local advisory file only.')
        body = ttk.Frame(self, padding=10)
        body.pack(fill='both', expand=True)
        ttk.Label(body, text='Known vulnerability review', style='Title.TLabel').pack(anchor='w')
        self.pages = ttk.Notebook(body)
        self.pages.pack(fill='both', expand=True)
        setup, results = ttk.Frame(self.pages, padding=10), ttk.Frame(self.pages, padding=10)
        self.pages.add(setup, text='What do you want to check?')
        self.pages.add(results, text='Results')
        self.results_page = results
        ttk.Label(setup, text='Check whether a specific software version appears in a list of known security problems (CVEs). '
                  'No file yet? Try the fake example below. This does not scan a website.',
                  wraplength=610, justify='left').pack(anchor='w', pady=(0, 6))
        fields = ttk.Frame(setup)
        fields.pack(fill='x')
        fields.columnconfigure(1, weight=1)
        for i, (label, var) in enumerate((('Who made it? (vendor)', self.vendor), ('Software name (product)', self.product), ('Exact version', self.version))):
            ttk.Label(fields, text=label).grid(row=i, column=0, sticky='w', padx=(0, 8), pady=3)
            ttk.Entry(fields, textvariable=var).grid(row=i, column=1, sticky='ew', pady=3)
        ttk.Label(setup, text='Known problems file — NVD JSON 2.0 (up to 10 MB)').pack(anchor='w', pady=(6, 2))
        row = ttk.Frame(setup)
        row.pack(fill='x')
        ttk.Entry(row, textvariable=self.feed).pack(side='left', fill='x', expand=True)
        ttk.Button(row, text='Browse', command=self.browse).pack(side='right', padx=(5, 0))
        ttk.Label(setup, text='Choose a downloaded NVD vulnerability list in JSON 2.0 format, not a Sentinel or ZAP report. '
                  'You can skip this feature if you do not have one.', wraplength=610, style='Muted.TLabel').pack(anchor='w')
        actions = ttk.Frame(setup)
        actions.pack(fill='x', pady=6)
        self.start_button = ttk.Button(actions, text='Check my software', command=self.start, style='Primary.TButton')
        self.start_button.pack(side='left')
        self.example_button = ttk.Button(actions, text='Try fake example', command=self.example)
        self.example_button.pack(side='left', padx=6)
        ttk.Label(setup, text='A match means a known problem may apply. It does not prove your software can be hacked. No match does not prove safety. Only exact version matches are checked.',
                  wraplength=610, style='Muted.TLabel').pack(anchor='w')
        self.output = detail_box(results, height=8)
        self.output.configure(state='disabled')
        scrollable(results, self.output)
        footer = ttk.Frame(body)
        footer.pack(side='bottom', fill='x', before=self.pages)
        ttk.Button(footer, text='Stop', command=lambda: self.cancel.set()).pack(side='right')
        ttk.Label(footer, textvariable=self.status, wraplength=570).pack(side='left')
        self.poll_timer = self.after(100, self.poll)

    def example(self):
        if self.busy:
            return
        result = cve_example()
        self.output.configure(state='normal')
        self.output.delete('1.0', 'end')
        self.output.insert('1.0', 'PRACTICE ONLY — NOT A REAL CVE\n\nImagine you own Demo App version 1.0. A pretend list of known problems includes that exact version.\n\n'
                           'Matches found: ' + str(len(result['matches'])) +
                           '\n\nWhat would you do in real life? Check the software maker’s security advice and install the appropriate fix.\n\n'
                           'This example uses fake data and is not saved to your project.')
        self.output.configure(state='disabled')
        self.pages.select(self.results_page)
        self.status.set('Fake example — no real software checked.')

    def browse(self):
        path = filedialog.askopenfilename(parent=self, filetypes=[('JSON', '*.json')])
        if path:
            self.feed.set(path)

    def start(self):
        if self.busy:
            return
        try:
            identity = identify(self.vendor.get(), self.product.get(), self.version.get())
            path = self.feed.get().strip()
            if not path:
                raise ValueError('Choose an NVD JSON 2.0 list of known problems, or click Try fake example first.')
            pid = self.app.store.project(self.app.project.get())
        except ValueError as exc:
            messagebox.showerror('Cannot start', str(exc), parent=self)
            return
        self.cancel = Event()
        cancel, queue = self.cancel, self.queue
        try:
            self.orchestrator.submit(lambda: assess(path, *identity, cancel=cancel),
                                     lambda result, error: queue.put((pid, result, error)), cancel)
        except RuntimeError as exc:
            self.status.set(str(exc))
            return
        self.busy = True
        self.start_button.configure(state='disabled')
        self.status.set('Reviewing local advisories…')

    def poll(self):
        try:
            pid, result, error = self.queue.get_nowait()
        except Empty:
            pass
        else:
            self.busy = False
            self.start_button.configure(state='normal')
            if error or self.cancel.is_set() or result is None:
                self.status.set('Review cancelled or could not complete.')
            else:
                c = result['coverage']
                lines = ['KNOWN PROBLEMS THAT MAY APPLY', *(c['matches'] or ['None in this file']), '', 'NEEDS A CLOSER LOOK',
                         *c['review'], '', c['limitations'], '', result['error']]
                self.output.configure(state='normal')
                self.output.delete('1.0', 'end')
                self.output.insert('1.0', '\n'.join(lines))
                self.output.configure(state='disabled')
                self.pages.select(self.results_page)
                self.status.set(f"{len(c['matches'])} matches · {len(c['review'])} require review")
                try:
                    self.app.store.save(pid, result)
                except Exception:
                    self.status.set('Results available; could not save to history.')
        if self.winfo_exists():
            self.poll_timer = self.after(100, self.poll)
