"""Desktop access to local file integrity checks and tool report review."""
from pathlib import Path
from queue import Empty, Queue
from threading import Event
import tkinter as tk
from tkinter import filedialog, ttk

from .desktop_theme import CANVAS, detail_box, scrollable
from .local_tools import inspect_integrity, review_report
from .help_examples import zap_example
from .orchestration import for_app
from .ui_lifecycle import watch_poll, watch_variables, bind_escape

REPORT_FORMATS = {
    'ZAP · Traditional JSON': ('zap', '*.json'),
    'ZAP · Detailed alert review': ('zap-detail', '*.json'),
    'Nmap · XML': ('nmap', '*.xml'),
    'Wireshark · Packet-list CSV': ('wireshark', '*.csv'),
}


class LocalUtilitiesWindow(tk.Toplevel):
    def __init__(self, app, **options):
        super().__init__(app, **options)
        watch_poll(self)
        bind_escape(self)
        self.title('Sentinel | Local utilities')
        self.geometry('760x550')
        self.minsize(600, 430)
        self.configure(background=CANVAS)
        self.orchestrator = for_app(app)
        self.queue = Queue()
        self.cancel_event = Event()
        self.bind('<Destroy>', self.cancel_on_destroy, add='+')
        self.busy = False
        self.controls = []
        self.status = tk.StringVar(value='Ready')
        self.integrity_path = tk.StringVar()
        self.expected_digest = tk.StringVar()
        self.bola_path = tk.StringVar()
        self.report_path = tk.StringVar()
        self.report_format = tk.StringVar(value=next(iter(REPORT_FORMATS)))

        body = ttk.Frame(self, padding=8, style='Canvas.TFrame')
        body.pack(fill='both', expand=True)
        notebook = ttk.Notebook(body)
        notebook.pack(fill='both', expand=True)
        notebook.enable_traversal()
        self.integrity_output = self.build_integrity(notebook)
        self.report_output = self.build_review(notebook)
        self.notebook = notebook
        self.bola_pane = ttk.Frame(notebook, padding=12)
        notebook.add(self.bola_pane, text='IDOR / BOLA')
        ttk.Label(self.bola_pane, text='Compare recorded API reads with the subjects allowed to read each object. '
                  'Use pseudonymous IDs and response object IDs from your test logs.',
                  style='Muted.TLabel', wraplength=540).pack(anchor='w', pady=(0, 8))
        self.file_field(self.bola_pane, 'Access policy and recorded reads (JSON)', self.bola_path,
                        lambda: [('JSON', '*.json')])
        row = ttk.Frame(self.bola_pane)
        row.pack(fill='x', pady=8)
        for label, command in [('Check object access', self.start_bola), ('Save example…', self.save_bola_example)]:
            button = ttk.Button(row, text=label, command=command)
            button.pack(side='left', padx=(0, 6))
            self.controls.append(button)
        self.bola_output = self.output_box(self.bola_pane)
        watch_variables(self, (self.bola_path,), lambda *_: self.clear_output(self.bola_output))
        watch_variables(self, (self.integrity_path, self.expected_digest),
                        lambda *_: self.clear_output(self.integrity_output))
        watch_variables(self, (self.report_path, self.report_format),
                        lambda *_: self.clear_output(self.report_output))

        footer = ttk.Frame(body, style='Canvas.TFrame')
        footer.pack(fill='x', pady=(8, 0))
        ttk.Label(footer, textvariable=self.status, style='Canvas.TLabel', wraplength=485).pack(side='left')
        self.stop_button = ttk.Button(footer, text='Stop', command=self.stop, state='disabled')
        self.stop_button.pack(side='right')
        self.poll_timer = self.after(80, self.poll)

    def build_integrity(self, notebook):
        pane = ttk.Frame(notebook, padding=8)
        notebook.add(pane, text='File integrity')
        ttk.Label(pane, text='Check whether a file has changed. A hash is like a fingerprint for a file; compare it with a trusted fingerprint from the file maker. This is not a virus scan.',
                  style='Muted.TLabel', wraplength=515).pack(anchor='w', pady=(0, 5))
        self.file_field(pane, 'File to check', self.integrity_path)
        ttk.Label(pane, text='Trusted file fingerprint (optional)').pack(anchor='w', pady=(7, 0))
        expected = ttk.Entry(pane, textvariable=self.expected_digest)
        expected.pack(fill='x', pady=(3, 0))
        self.controls.append(expected)
        self.action(pane, 'Calculate hashes', self.start_integrity)
        return self.output_box(pane)

    def build_review(self, notebook):
        pane = ttk.Frame(notebook, padding=8)
        notebook.add(pane, text='Tool report review')
        ttk.Label(pane, text='Read a security report made by another tool. If you have never used ZAP, Nmap or Wireshark, try the fake report first. You do not need to find a file.', style='Muted.TLabel').pack(anchor='w', pady=(0, 9))
        ttk.Label(pane, text='Report format').pack(anchor='w')
        formats = ttk.Combobox(pane, textvariable=self.report_format, values=list(REPORT_FORMATS), state='readonly')
        formats.pack(fill='x', pady=(3, 7))
        self.controls.append(formats)
        self.report_help = tk.StringVar()
        ttk.Label(pane, textvariable=self.report_help, wraplength=610, justify='left', style='Muted.TLabel').pack(anchor='w', pady=(0, 5))
        watch_variables(self, (self.report_format,), self.update_report_help)
        self.update_report_help()
        self.file_field(pane, 'Saved report from that tool', self.report_path,
                        lambda: [(self.report_format.get(), REPORT_FORMATS[self.report_format.get()][1]), ('All files', '*')])
        buttons = ttk.Frame(pane)
        buttons.pack(fill='x', pady=5)
        self.action(buttons, 'Read my report', self.start_review)
        self.action(buttons, 'Try fake ZAP report', self.show_zap_example)
        return self.output_box(pane)

    def update_report_help(self, *_):
        fmt = REPORT_FORMATS[self.report_format.get()][0]
        self.report_help.set({
            'zap': 'In OWASP ZAP, export a Traditional JSON report using its report generator. Choose that .json file here. Sentinel does not generate a ZAP scan yet.',
            'zap-detail': 'Use the same ZAP Traditional JSON file. This option explains the individual warnings and suggested fixes.',
            'nmap': 'Choose an XML report exported by Nmap, not a program installer or a screenshot.',
            'wireshark': 'Choose a packet-list CSV exported from Wireshark, not a capture file (.pcap).'
        }[fmt])

    def show_zap_example(self):
        if self.busy:
            return
        rows = zap_example()
        self.show_output(self.report_output,
                         'PRACTICE ONLY — FAKE REPORT\n\n'
                         'Imagine another scanner found one possible problem on a pretend website.\n'
                         'Warnings reported: ' + str(rows['Alert types reported']) +
                         '\nRisk: Low\n\nSuggested action: Ask the website owner to check its browser protection settings.'
                         '\n\nNo website was tested. Real ZAP reports may contain false alarms.')
        self.status.set('Fake ZAP report read. No file needed.')

    def file_field(self, pane, label, variable, filetypes=lambda: [('All files', '*')]):
        ttk.Label(pane, text=label).pack(anchor='w')
        row = ttk.Frame(pane)
        row.pack(fill='x', pady=(3, 0))

        def browse():
            path = filedialog.askopenfilename(parent=self, filetypes=filetypes())
            if path:
                variable.set(path)

        button = ttk.Button(row, text='Browse…', command=browse)
        button.pack(side='right', padx=(6, 0))
        entry = ttk.Entry(row, textvariable=variable)
        entry.pack(side='left', fill='x', expand=True)
        self.controls.extend((entry, button))

    def action(self, pane, label, command):
        button = ttk.Button(pane, text=label, command=command, style='Primary.TButton')
        button.pack(anchor='w', pady=5)
        self.controls.append(button)

    def output_box(self, pane):
        frame = ttk.Frame(pane)
        frame.pack(fill='both', expand=True)
        output = detail_box(frame, height=5)
        output.configure(state='disabled')
        scrollable(frame, output)
        return output

    def clear_output(self, output):
        self.show_output(output, '')
        if not self.busy:
            self.status.set('Ready')

    @staticmethod
    def show_output(output, text):
        output.configure(state='normal')
        output.delete('1.0', 'end')
        output.insert('1.0', text)
        output.configure(state='disabled')

    def start_integrity(self):
        path, expected = self.integrity_path.get(), self.expected_digest.get()
        self.start(path, self.integrity_output, lambda cancel: inspect_integrity(path, expected, cancel))

    def save_bola_example(self):
        destination = filedialog.asksaveasfilename(parent=self, defaultextension='.json',
                                                   initialfile='example-object-reads.json', filetypes=[('JSON', '*.json')])
        if destination:
            try:
                template = Path(__file__).with_name('examples') / 'object-reads.json'
                Path(destination).write_bytes(template.read_bytes())
            except OSError:
                self.status.set('Could not save the example.')
                return
            self.bola_path.set(destination)
            self.status.set('Example saved. Replace the sample policy and responses with your test evidence.')

    def start_bola(self):
        path = self.bola_path.get()
        self.start(path, self.bola_output, lambda _: review_report(path, 'bola'))

    def start_review(self):
        path = self.report_path.get()
        format_name, _ = REPORT_FORMATS[self.report_format.get()]
        self.start(path, self.report_output, lambda cancel: review_report(path, format_name))

    def start(self, path, output, operation):
        if self.busy:
            return
        if not path:
            self.status.set('Choose a file first.')
            return

        cancel = self.cancel_event = Event()
        queue = self.queue
        self.show_output(output, '')

        def read():
            try:
                return {'rows': operation(cancel)}
            except ValueError as exc:
                return {'status': 'failed', 'error': str(exc)}
            except OSError:
                return {'status': 'failed', 'error': 'Could not open or read the selected file.'}

        try:
            self.job = self.orchestrator.submit(
                read, lambda result, error: queue.put((result, error)), cancel)
        except RuntimeError as exc:
            self.status.set(str(exc))
            return
        self.busy = True
        self.active_output = output
        for control in self.controls:
            control.state(['disabled'])
        self.stop_button.state(['!disabled'])
        self.status.set('Queued…')

    def stop(self):
        self.cancel_event.set()
        self.stop_button.state(['disabled'])
        self.status.set('Stopping…')

    def poll(self):
        try:
            result, error = self.queue.get_nowait()
        except Empty:
            if self.busy and self.job.state == 'running' and not self.cancel_event.is_set():
                self.status.set('Reading file…')
        else:
            self.busy = False
            for control in self.controls:
                control.state(['!disabled'])
            self.stop_button.state(['disabled'])
            error = error or result.get('error')
            if error:
                self.status.set(error)
            else:
                lines = []
                for label, value in result['rows'].items():
                    if isinstance(value, dict):
                        lines.append(label)
                        lines.extend(f'  {name}  {count}' for name, count in value.items())
                    else:
                        lines.append(f'{label}  {value}')
                self.show_output(self.active_output, '\n'.join(lines))
                self.status.set('Completed')
        self.poll_timer = self.after(80, self.poll)

    def cancel_on_destroy(self, event):
        if event.widget is self:
            self.cancel_event.set()
