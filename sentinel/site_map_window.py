"""Simple read-only public page map desktop window."""
import tkinter as tk
from tkinter import ttk, messagebox
from queue import Queue, Empty
from threading import Event

from .engine import Target
from .site_map import map_site, MAX_PAGES
from .desktop_theme import detail_box, scrollable
from .orchestration import for_app
from .ui_lifecycle import watch_poll, bind_escape


class SiteMapWindow(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app, name='site_map')
        self.title('Sentinel | Website mapper')
        self.geometry('840x580')
        self.minsize(680, 450)
        self.queue = Queue()
        self.cancel = Event()
        self.busy = False
        self.rows = {}
        self.orchestrator = for_app(app)
        watch_poll(self)
        bind_escape(self)
        self.bind('<Destroy>', lambda e: self.cancel.set() if e.widget is self else None, add='+')
        body = ttk.Frame(self, padding=12)
        body.pack(fill='both', expand=True)
        ttk.Label(body, text='Website mapper', style='Title.TLabel').pack(anchor='w')
        ttk.Label(body, text='See how publicly linked pages connect and where ordinary forms appear. '
                  'No login, hidden-page guessing, form submission or security bypass.',
                  wraplength=640, justify='left').pack(anchor='w', pady=5)
        self.url = tk.StringVar(value='')
        controls = ttk.Frame(body)
        controls.pack(fill='x', pady=6)
        self.entry = ttk.Entry(controls, textvariable=self.url)
        self.entry.pack(side='left', fill='x', expand=True)
        self.start_button = ttk.Button(controls, text='Map website', command=self.start, style='Primary.TButton')
        self.start_button.pack(side='left', padx=5)
        self.stop_button = ttk.Button(controls, text='Stop', command=lambda: self.cancel.set(), state='disabled')
        self.stop_button.pack(side='left')
        self.status = tk.StringVar(value='Enter the authorized website address, including https://.')
        ttk.Label(body, textvariable=self.status, wraplength=700).pack(anchor='w', pady=4)
        frame = ttk.Frame(body)
        frame.pack(fill='both', expand=True)
        self.tree = ttk.Treeview(frame, columns=('http', 'forms'), show='tree headings', height=10)
        self.tree.heading('#0', text='Page / link from parent')
        self.tree.heading('http', text='HTTP')
        self.tree.heading('forms', text='Forms')
        self.tree.column('#0', width=440)
        self.tree.column('http', width=75, stretch=False)
        self.tree.column('forms', width=75, stretch=False)
        scrollable(frame, self.tree)
        self.tree.bind('<<TreeviewSelect>>', self.selected)
        self.detail = detail_box(body, height=5)
        self.detail.pack(fill='x', pady=(8, 0))
        self.say('Click a mapped page to see its form summary. A form is not necessarily a security problem.')
        self.poll_timer = self.after(100, self.poll)

    def say(self, text):
        self.detail.configure(state='normal')
        self.detail.delete('1.0', 'end')
        self.detail.insert('1.0', text)
        self.detail.configure(state='disabled')

    def start(self):
        if self.busy:
            return
        try:
            target = Target.parse(self.url.get())
        except ValueError as exc:
            messagebox.showerror('Website address', str(exc), parent=self)
            return
        if not messagebox.askokcancel('Approve website map', 'Start: ' + target.url +
                '\n\nUp to ' + str(MAX_PAGES) + ' read-only GET requests to publicly linked pages on this exact origin. '
                'Confirm permission for these pages and that ordinary navigation is read-only.',
                parent=self, default=messagebox.CANCEL):
            return
        self.cancel = Event()
        cancel, queue = self.cancel, self.queue
        try:
            self.orchestrator.submit(lambda: map_site(target.url, True, cancel),
                                     lambda result, error: queue.put((result, error)), cancel)
        except RuntimeError as exc:
            self.status.set(str(exc))
            return
        self.busy = True
        self.entry.configure(state='disabled')
        self.start_button.configure(state='disabled')
        self.stop_button.configure(state='normal')
        self.tree.delete(*self.tree.get_children())
        self.rows.clear()
        self.status.set('Reading publicly linked pages…')

    def selected(self, _event=None):
        selection = self.tree.selection()
        if not selection:
            return
        row = self.rows.get(selection[0])
        if not row:
            return
        self.say('Page: ' + row['path'] + '\nHTTP response: ' + str(row['http'] or 'Not received') +
                 '\nForms: ' + (str(row['forms']) if row['read'] else 'Not read') +
                 '\nNamed ordinary inputs: ' + (', '.join(row['inputs']) or 'None observed') +
                 '\nNo form was submitted. No vulnerability has been established.')

    def poll(self):
        try:
            result, error = self.queue.get_nowait()
        except Empty:
            pass
        else:
            self.busy = False
            self.entry.configure(state='normal')
            self.start_button.configure(state='normal')
            self.stop_button.configure(state='disabled')
            if error or not result:
                self.status.set('Map could not finish.')
            else:
                parents = {}
                for i, row in enumerate(result['rows']):
                    iid = str(i)
                    self.rows[iid] = row
                    self.tree.insert(parents.get(row['parent'], ''), 'end', iid=iid,
                                     text=row['path'], values=(row['http'] or '—',
                                     row['forms'] if row['read'] else '—'), open=True)
                    parents[row['path']] = iid
                self.status.set(str(len(self.rows)) + ' pages attempted • ' + result['message'])
        if self.winfo_exists():
            self.poll_timer = self.after(100, self.poll)
