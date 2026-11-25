"""Compact demonstration of access-control failures and correct behavior."""
import tkinter as tk
from tkinter import ttk
from queue import Queue, Empty
from threading import Event

from .access_lab import demonstrate
from .desktop_theme import detail_box, scrollable
from .orchestration import for_app
from .ui_lifecycle import watch_poll, bind_escape


class AccessLabWindow(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app, name='access_lab')
        self.title('Sentinel | Access control lab')
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
        ttk.Label(body, text='Can someone see a private record?', style='Title.TLabel').pack(anchor='w')
        ttk.Label(body, text='Run a real HTTP test against Sentinel’s temporary local practice server. '
                  'It compares a deliberately weak example with a protected one using fake users and records.',
                  wraplength=610, justify='left').pack(anchor='w', pady=(4, 8))
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
        self.say('WHY THIS MATTERS\nA website must check both who you are and whether you may see a particular record. '
                 'Being signed in is not enough. Start the lab to compare the responses from a weak and a protected example.')
        self.poll_timer = self.after(100, self.poll)

    def say(self, text):
        self.output.configure(state='normal')
        self.output.delete('1.0', 'end')
        self.output.insert('1.0', text)
        self.output.configure(state='disabled')

    def start(self):
        if self.busy:
            return
        self.cancel = Event()
        cancel, queue = self.cancel, self.queue
        try:
            self.orchestrator.submit(lambda: demonstrate(cancel),
                                     lambda result, error: queue.put((result, error)), cancel)
        except RuntimeError as exc:
            self.status.set(str(exc))
            return
        self.busy = True
        self.tree.delete(*self.tree.get_children())
        self.start_button.configure(state='disabled')
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
            self.stop.configure(state='disabled')
            if error or not result or result.get('status') != 'completed':
                self.status.set('Practice test incomplete or cancelled.')
                self.say('No conclusion. Run the local test again.')
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
