"""Desktop controls for a bounded, read-only live website input check."""
import tkinter as tk
from tkinter import ttk, messagebox
from queue import Queue, Empty
from threading import Event

from .desktop_theme import detail_box, scrollable
from .live_input import validate, inspect_input
from .orchestration import for_app
from .ui_lifecycle import watch_poll, bind_escape


class LiveInputWindow(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app, name='live_input')
        self.title('Sentinel | Live website input check')
        self.geometry('740x520')
        self.minsize(650, 450)
        self.queue = Queue()
        self.cancel = Event()
        self.busy = False
        self.orchestrator = for_app(app)
        watch_poll(self)
        bind_escape(self)
        self.bind('<Destroy>', lambda e: self.cancel.set() if e.widget is self else None, add='+')
        body = ttk.Frame(self, padding=12)
        body.pack(fill='both', expand=True)
        ttk.Label(body, text='Does your website display input safely?', style='Title.TLabel').pack(anchor='w')
        ttk.Label(body, text='Choose a read-only page you own or have permission to test. '
                  'For example, a search page that displays your search words. '
                  'Sentinel sends two harmless inputs and checks the returned HTML.',
                  wraplength=610, justify='left').pack(anchor='w', pady=6)
        self.url = tk.StringVar(value='')
        self.parameter = tk.StringVar(value='q')
        ttk.Label(body, text='Page address, without the question mark or search words').pack(anchor='w')
        self.url_entry = ttk.Entry(body, textvariable=self.url)
        self.url_entry.pack(fill='x', pady=(2, 6))
        ttk.Label(body, text='Input name (e.g. q in /search?q=hello)').pack(anchor='w')
        self.param_entry = ttk.Entry(body, textvariable=self.parameter)
        self.param_entry.pack(fill='x', pady=(2, 6))
        footer = ttk.Frame(body)
        footer.pack(side='bottom', fill='x', pady=(8, 0))
        self.status = tk.StringVar(value='Ready — no website contacted.')
        ttk.Label(footer, textvariable=self.status, wraplength=430).pack(side='left')
        self.stop_button = ttk.Button(footer, text='Stop', command=lambda: self.cancel.set(), state='disabled')
        self.stop_button.pack(side='right')
        self.start_button = ttk.Button(footer, text='Check my page', command=self.start, style='Primary.TButton')
        self.start_button.pack(side='right', padx=6)
        area = ttk.Frame(body)
        area.pack(fill='both', expand=True)
        self.output = detail_box(area)
        scrollable(area, self.output)
        self.say('EXAMPLE\nIf your search address ends in /search?q=hello, enter the page address ending in /search and input name q.\n\n'
                 'Do not choose a page that changes or deletes data. No login, scripts, or redirect following. '
                 'An unsafe-looking response is a reason to investigate, not proof that someone can execute code.')
        self.poll_timer = self.after(100, self.poll)

    def say(self, text):
        self.output.configure(state='normal')
        self.output.delete('1.0', 'end')
        self.output.insert('1.0', text)
        self.output.configure(state='disabled')

    def start(self):
        if self.busy:
            return
        try:
            target, parameter = validate(self.url.get(), self.parameter.get())
        except ValueError as exc:
            messagebox.showerror('Check page details', str(exc), parent=self)
            return
        if not messagebox.askokcancel('Confirm read-only test',
                'Page: ' + target.url + '\nInput: ' + parameter +
                '\n\nTwo anonymous GET requests with harmless markers. Confirm that this input is read-only and you have permission to test it.',
                parent=self, default=messagebox.CANCEL):
            return
        self.cancel = Event()
        cancel, queue = self.cancel, self.queue
        try:
            self.orchestrator.submit(lambda: inspect_input(target.url, parameter, True, cancel),
                                     lambda result, error: queue.put((result, error)), cancel)
        except RuntimeError as exc:
            self.status.set(str(exc))
            return
        self.busy = True
        for control in (self.url_entry, self.param_entry, self.start_button):
            control.configure(state='disabled')
        self.stop_button.configure(state='normal')
        self.status.set('Checking page response…')
        self.say('Sending up to two read-only requests to the approved page.')

    def poll(self):
        try:
            result, error = self.queue.get_nowait()
        except Empty:
            pass
        else:
            self.busy = False
            for control in (self.url_entry, self.param_entry, self.start_button):
                control.configure(state='normal')
            self.stop_button.configure(state='disabled')
            if error or not result:
                self.status.set('Check incomplete.')
                self.say(error or 'No result. Check the address and connection.')
            else:
                self.status.set(result['verdict'])
                self.say('RESULT: ' + result['verdict'] + '\n\nPage: ' + result['target'] +
                         '\nInput: ' + result['parameter'] +
                         '\nRequests attempted: ' + str(result['requests']) +
                         '\nFirst HTTP response: ' + str(result['baseline_http'] or 'Not received') +
                         '\nSecond HTTP response: ' + str(result['probe_http'] or 'Not received') +
                         '\n\nWHAT HAPPENED\n' + result['message'] +
                         '\n\nHOW TO FIX\nUse safe text rendering and context-appropriate output encoding. '
                         'After changing the page, repeat the check. No response body was saved.')
        if self.winfo_exists():
            self.poll_timer = self.after(100, self.poll)
