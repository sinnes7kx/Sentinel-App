"""Compact demonstration of access-control failures and correct behavior."""
import tkinter as tk
from tkinter import ttk
from queue import Queue, Empty
from threading import Event
from pathlib import Path
import webbrowser

from .access_lab import demonstrate
from .database_lab import demonstrate_database
from .desktop_theme import detail_box, scrollable
from .orchestration import for_app
from .ui_lifecycle import watch_poll, bind_escape


class AccessLabWindow(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app, name='access_lab')
        self.title('Sentinel | Verification lab')
        self.geometry('760x490')
        self.minsize(650, 420)
        self.cancel = Event()
        self.queue = Queue()
        self.busy = False
        self.orchestrator = for_app(app)
        watch_poll(self)
        bind_escape(self)
        self.bind('<Destroy>', lambda e: self.cancel.set() if e.widget is self else None, add='+')
        body = ttk.Frame(self, padding=10)
        body.pack(fill='both', expand=True)
        ttk.Label(body, text='Verify a security failure', style='Title.TLabel').pack(anchor='w')
        self.kind = tk.StringVar(value='Access control')
        self.selector = ttk.Combobox(body, textvariable=self.kind, state='readonly',
                                     values=('Access control', 'Database input handling', 'XSS (browser practice)'))
        self.selector.pack(anchor='w', fill='x', pady=(4, 4))
        self.description = tk.StringVar(value='')
        ttk.Label(body, textvariable=self.description, wraplength=610,
                  justify='left').pack(anchor='w', pady=(4, 8))
        footer = ttk.Frame(body)
        footer.pack(side='bottom', fill='x', pady=(6, 0))
        self.status = tk.StringVar(value='Local practice only. No external target is contacted.')
        ttk.Label(footer, textvariable=self.status, wraplength=460).pack(side='left')
        self.stop = ttk.Button(footer, text='Stop', command=lambda: self.cancel.set(), state='disabled')
        self.stop.pack(side='right')
        self.start_button = ttk.Button(footer, text='Run live lab', command=self.start, style='Primary.TButton')
        self.start_button.pack(side='right', padx=6)
        table = ttk.Frame(body)
        table.pack(fill='x')
        self.tree = ttk.Treeview(table, columns=('user', 'weak', 'protected'), show='headings', height=3)
        for key, title, width in (('user', 'Scenario', 170), ('weak', 'Weak example', 155),
                                  ('protected', 'Protected example', 155)):
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, minwidth=90)
        self.tree.pack(fill='x')
        self.tree.tag_configure('owner', foreground='#78bdf9')
        self.tree.tag_configure('failure', foreground='#ff9060')
        area = ttk.Frame(body)
        area.pack(fill='both', expand=True, pady=(8, 0))
        self.output = detail_box(area, height=7)
        scrollable(area, self.output)
        self.selector.bind('<<ComboboxSelected>>', self.change_kind)
        self.change_kind()
        self.poll_timer = self.after(100, self.poll)

    def change_kind(self, _event=None):
        if self.busy:
            return
        self.tree.delete(*self.tree.get_children())
        self.status.set('Local practice only. No external target is contacted.')
        self.start_button.configure(text='Open browser example' if self.kind.get() == 'XSS (browser practice)' else 'Run live lab')
        if self.kind.get() == 'XSS (browser practice)':
            self.description.set('See why a website should display comments as words instead of running them as instructions.')
            self.say('Click Open browser example. Two isolated frames compare a fixed harmless script with the same text displayed safely. Look for the message that changes. No real site is tested, and Sentinel does not automatically record browser execution.')
        elif self.kind.get() == 'Database input handling':
            self.description.set('Run real SQLite queries against two synthetic records in memory. Compare unsafe SQL construction with bound parameters.')
            self.say('WHY THIS MATTERS\nUser input should remain data, not become part of a database instruction. This experiment tests a normal record ID and a fixed unexpected expression.')
        else:
            self.description.set('Run real HTTP requests against a temporary local practice server with fake users and records.')
            self.say('WHY THIS MATTERS\nA website must check both who you are and whether you may see a particular record. Being signed in is not enough.')

    def say(self, text):
        self.output.configure(state='normal')
        self.output.delete('1.0', 'end')
        self.output.insert('1.0', text)
        self.output.configure(state='disabled')

    def start(self):
        if self.busy:
            return
        if self.kind.get() == 'XSS (browser practice)':
            page = Path(__file__).with_name('xss_practice.html')
            try:
                opened = page.is_file() and webbrowser.open(page.resolve().as_uri())
            except (OSError, webbrowser.Error):
                opened = False
            self.status.set('Observe the two browser examples. No automatic result recorded.' if opened else
                            'Browser example could not open. Check your default browser and source files.')
            return
        self.cancel = Event()
        cancel, queue = self.cancel, self.queue
        self.running_kind = self.kind.get()
        operation = demonstrate_database if self.running_kind == 'Database input handling' else demonstrate
        try:
            self.orchestrator.submit(lambda: operation(cancel),
                                     lambda result, error: queue.put((result, error)), cancel)
        except RuntimeError as exc:
            self.status.set(str(exc))
            return
        self.busy = True
        self.tree.delete(*self.tree.get_children())
        self.start_button.configure(state='disabled')
        self.selector.configure(state='disabled')
        self.stop.configure(state='normal')
        self.status.set('Running local practice test…')

    def poll(self):
        try:
            result, error = self.queue.get_nowait()
        except Empty:
            pass
        else:
            self.busy = False
            self.start_button.configure(state='normal')
            self.selector.configure(state='readonly')
            self.stop.configure(state='disabled')
            if error or not result or result.get('status') != 'completed':
                self.status.set('Practice test incomplete or cancelled.')
                self.say('No conclusion. Run the local test again.')
            elif self.running_kind == 'Database input handling':
                for i, row in enumerate(result['rows']):
                    def label(kind):
                        return (str(row[kind + '_count']) + ' record(s)' +
                                (' · second row' if row[kind + '_second_row'] else ''))
                    self.tree.insert('', 'end', values=(row['scenario'], label('weak'), label('protected')),
                                     tags=('owner' if i == 0 else 'failure',))
                self.status.set('Practice test completed. In-memory database closed.')
                self.say('CONFIRMED IN THE LAB\nThe unexpected input was interpreted as a SQL expression in the weak example and selected the second synthetic record. The parameterized version treated the input as data and returned no record.\n\nWHY IT MATTERS\nUnsafe query construction may let input change database behavior. This experiment does not establish login bypass or data exposure on a real website.\n\nHOW TO FIX\nUse parameterized queries, validate expected input types, and enforce authorization separately.')
            else:
                for i, row in enumerate(result['rows']):
                    def label(kind):
                        return str(row[kind + '_status']) + (' · record visible' if row[kind + '_record_visible'] else ' · denied')
                    self.tree.insert('', 'end', values=(row['scenario'], label('weak'), label('protected')),
                                     tags=('owner' if i == 0 else 'failure',))
                self.status.set('Practice test completed. Temporary server closed.')
                self.say('WHAT WAS DEMONSTRATED\nThe weak example returned the fake private record to a different user '
                         'and to a visitor who was not signed in. The protected example rejected both requests and allowed '
                         'the owner to see the record.\n\nWHY IT MATTERS\nOn a real website, a similar missing authorization check '
                         'could disclose private records.\n\nHOW TO FIX\nEnforce server-side authentication and record-level '
                         'authorization on every request. Test both permitted and denied users.\n\n'
                         'This is a deliberately vulnerable synthetic fixture, not a finding on your website.')
        if self.winfo_exists():
            self.poll_timer = self.after(100, self.poll)
