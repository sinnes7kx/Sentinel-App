"""Compact local advisory matching window."""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from threading import Event
from queue import Queue, Empty
from .desktop_theme import detail_box, scrollable
from .ui_lifecycle import watch_poll, bind_escape
from .cve_review import assess, identify
from .orchestration import for_app


class CVEWindow(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app, name='cve_review')
        self.app = app
        self.title('Sentinel | CVE review')
        self.geometry('740x480')
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
        self.pages.add(setup, text='Software identity')
        self.pages.add(results, text='Results')
        self.results_page = results
        ttk.Label(setup, text='Enter verified software identity using exact NVD CPE tokens. '
                  'A website banner alone is not proof of the installed build.',
                  wraplength=610, justify='left').pack(anchor='w', pady=(0, 6))
        fields = ttk.Frame(setup)
        fields.pack(fill='x')
        fields.columnconfigure(1, weight=1)
        for i, (label, var) in enumerate((('Vendor', self.vendor), ('Product', self.product), ('Version', self.version))):
            ttk.Label(fields, text=label).grid(row=i, column=0, sticky='w', padx=(0, 8), pady=3)
            ttk.Entry(fields, textvariable=var).grid(row=i, column=1, sticky='ew', pady=3)
        ttk.Label(setup, text='Local NVD CVE JSON 2.0 file (max 10 MiB)').pack(anchor='w', pady=(6, 2))
        row = ttk.Frame(setup)
        row.pack(fill='x')
        ttk.Entry(row, textvariable=self.feed).pack(side='left', fill='x', expand=True)
        ttk.Button(row, text='Browse', command=self.browse).pack(side='right', padx=(5, 0))
        self.start_button = ttk.Button(setup, text='Review CVEs', command=self.start, style='Primary.TButton')
        self.start_button.pack(anchor='w', pady=6)
        ttk.Label(setup, text='Exact-version matches only. Version ranges and platform conditions require manual review.',
                  wraplength=610, style='Muted.TLabel').pack(anchor='w')
        self.output = detail_box(results, height=8)
        self.output.configure(state='disabled')
        scrollable(results, self.output)
        footer = ttk.Frame(body)
        footer.pack(side='bottom', fill='x', before=self.pages)
        ttk.Button(footer, text='Stop', command=lambda: self.cancel.set()).pack(side='right')
        ttk.Label(footer, textvariable=self.status, wraplength=570).pack(side='left')
        self.poll_timer = self.after(100, self.poll)

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
                raise ValueError('Choose an advisory file.')
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
                lines = ['EXACT VERSION MATCHES', *c['matches'], '', 'MANUAL REVIEW REQUIRED',
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
