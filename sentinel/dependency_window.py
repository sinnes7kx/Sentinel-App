"""Beginner interface for offline dependency advisory assessment."""
import json
from pathlib import Path
from queue import Queue, Empty
from threading import Event
from .orchestration import for_app
from .ui_lifecycle import watch_poll, bind_escape
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from .dependencies import assess
from .desktop_theme import CANVAS, detail_box, scrollable


class DependencyWindow(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app)
        watch_poll(self)
        bind_escape(self)
        self.title('Sentinel | Local dependency check')
        self.geometry('800x520')
        self.minsize(720, 460)
        self.configure(background=CANVAS)
        self.orchestrator = for_app(app)
        self.app = app
        self.cancel_event = Event()
        self.bind('<Destroy>', lambda e: self.cancel_event.set() if e.widget is self else None, add='+')
        self.queue = Queue()
        self.busy = False
        self.result = None
        self.inventory = tk.StringVar()
        self.feed = tk.StringVar()
        self.format = tk.StringVar(value='requirements')
        self.status = tk.StringVar(value='Your files stay on this computer. No packages are installed or executed.')
        body = ttk.Frame(self, padding=10)
        body.pack(fill='both', expand=True)
        ttk.Label(body, text='Local dependency check', style='Title.TLabel').pack(anchor='w', pady=(0, 4))
        self.pages = ttk.Notebook(body)
        self.pages.pack(fill='both', expand=True)
        self.pages.enable_traversal()
        files = self.files_page = ttk.Frame(self.pages, padding=10)
        results = self.results_page = ttk.Frame(self.pages, padding=8)
        self.pages.add(files, text='Choose files')
        self.pages.add(results, text='Results')
        ttk.Label(files, text='Choose a requirements.txt or pip inspect JSON file and a trusted local OSV advisory JSON array. No online lookup is performed.', wraplength=670).pack(anchor='w', pady=(0, 5))
        ttk.Button(files, text='Load synthetic example', command=self.load_example).pack(anchor='w', pady=(0, 6))
        for label, variable in [('1. Choose your package inventory', self.inventory), ('2. Choose a local OSV advisory JSON array', self.feed)]:
            ttk.Label(files, text=label).pack(anchor='w')
            row = ttk.Frame(files)
            row.pack(fill='x', pady=5)
            ttk.Entry(row, textvariable=variable).pack(side='left', fill='x', expand=True)
            ttk.Button(row, text='Browse…', command=lambda v=variable: self.choose(v)).pack(side='right', padx=8)
        row = ttk.Frame(files)
        row.pack(fill='x')
        for text, value in [('Requirements file', 'requirements'), ('pip inspect JSON inventory', 'pip-inspect')]:
            ttk.Radiobutton(row, text=text, variable=self.format, value=value).pack(side='left', padx=6)
        row = ttk.Frame(files)
        row.pack(fill='x', pady=6)
        self.button = ttk.Button(row, text='3. Check these files', command=self.start)
        self.button.pack(side='left')
        footer = ttk.Frame(body)
        footer.pack(side='bottom', fill='x', before=self.pages, pady=(4, 0))
        ttk.Button(footer, text='Stop', command=lambda: self.cancel_event.set()).pack(side='right')
        ttk.Button(footer, text='Export JSON', command=self.export).pack(side='right', padx=6)
        ttk.Label(footer, textvariable=self.status, wraplength=470, justify='left').pack(side='left', fill='x', expand=True)
        self.tree = ttk.Treeview(results, columns=('package', 'version', 'result'), show='headings', height=8)
        for column, label in [('package', 'Package'), ('version', 'Version'), ('result', 'Result')]:
            self.tree.heading(column, text=label)
        self.tree.configure(height=5)
        self.tree.pack(fill='both', expand=True)
        self.tree.bind('<<TreeviewSelect>>', self.selected)
        self.detail = detail_box(results, height=5)
        self.detail.pack(fill='both', expand=True, pady=8)
        self.say('Affected: an advisory matches this version.\nNo match in supplied feed: only these records were checked.\nUnknown: more information is needed.\n\nA result is not proof of exploitability or overall safety. Feed freshness is not verified.')
        self.poll_timer = self.after(100, self.poll)

    def load_example(self):
        if self.busy:
            return
        base = Path(__file__).resolve().parents[1] / 'examples' / 'dependencies'
        inventory, feed = base / 'requirements.txt', base / 'advisories-synthetic.json'
        if not inventory.is_file() or not feed.is_file():
            self.status.set('Example files are not included in this installation.')
            return
        self.inventory.set(str(inventory))
        self.feed.set(str(feed))
        self.format.set('requirements')
        self.status.set('Synthetic example loaded. Click Check these files to try it; not real vulnerability data.')

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
        if hasattr(self.app, 'store'):
            try:
                self.project_id = self.app.store.project(self.app.project.get())
            except ValueError as exc:
                self.busy = False
                messagebox.showerror('Project needed', str(exc), parent=self)
                return
        self.result = None
        self.tree.delete(*self.tree.get_children())
        self.button.configure(state='disabled')
        self.status.set('Reading local files…')
        cancel = self.cancel_event = Event()
        queue = self.queue
        try:
            self.job = self.orchestrator.submit(
                lambda: assess(inventory, feed, format, cancel=cancel),
                lambda result, error: queue.put((result, error)), cancel)
        except RuntimeError as exc:
            self.queue.put((None, str(exc)))

    def poll(self):
        if self.busy and hasattr(self, 'job'):
            self.status.set('Stopping…' if self.cancel_event.is_set() else self.job.state.capitalize() + ' • local files only')
        try:
            result, error = self.queue.get_nowait()
            self.busy = False
            self.button.configure(state='normal')
            self.result = result
            self.pages.select(self.results_page)
            if error:
                self.status.set('Assessment could not complete.')
                self.say(error)
            else:
                if hasattr(self.app, 'store'):
                    from .dependency_result import scan_record
                    self.app.store.save(self.project_id, scan_record(result))
                summary = result['summary']
                self.status.set(f"{summary['affected']} affected • {summary['unknown']} unknown • {summary['unsupported_inventory_entries']} unsupported entries. Coverage remains partial.")
                for index, package in enumerate(result['packages']):
                    self.tree.insert('', 'end', iid=str(index), values=(package['name'], package['version'], package['status'].replace('_', ' ')))
                self.say('Select a package for evidence and next steps.\n\nUnsupported inventory entries:\n' + json.dumps(result['unsupported_inventory_entries'], indent=2))
        except Empty:
            pass
        except Exception as exc:
            self.status.set('Local history/UI error: ' + type(exc).__name__ + '. You can still export the result.')
        if self.winfo_exists():
            self.poll_timer = self.after(100, self.poll)

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
