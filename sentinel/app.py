from .ui_lifecycle import watch_poll, watch_variables
from .desktop_theme import SEVERITY_COLORS, configure_theme, detail_box, scrollable
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from threading import Event
from .orchestration import for_app
from queue import Queue, Empty
from pathlib import Path
from .engine import Target, scan, compare
from .standard_assessment import standard_scan
from .store import Store
from .dnscheck import domain_name
import json
from .report import html_report


class DesktopUnavailable(RuntimeError):
    """Tk could not initialize the desktop window."""


class App(tk.Tk):
    def __init__(self):
        try:
            super().__init__()
        except tk.TclError as exc:
            raise DesktopUnavailable(str(exc)) from exc
        watch_poll(self)
        self.title('Sentinel')
        self.geometry('1280x780')
        self.minsize(960, 620)
        configure_theme(self)
        self.orchestrator = for_app(self)
        self.store = Store()
        self.queue = Queue()
        self.current = None
        self.current_id = None
        self.records = []
        self.busy = False
        self.cancel_event = Event()
        self.protocol('WM_DELETE_WINDOW', self.close)

        self.project = tk.StringVar(value='My website')
        self.url = tk.StringVar(value='https://')
        self.dns = tk.StringVar()
        self.assessment_profile = tk.StringVar(value='Quick')
        self.auth = tk.BooleanVar()
        self.status = tk.StringVar(value='Ready')
        self.summary = tk.StringVar(value='No assessment selected')
        self.observation_count = tk.StringVar(value='—')
        self.assessment_count = tk.StringVar(value='0')

        self.highest = tk.StringVar(value='—')
        self.selection_title = tk.StringVar(value='Select a finding')
        self.selection_meta = tk.StringVar(value='Choose a row to inspect its evidence.')
        header = ttk.Frame(self, padding=(16, 7), style='Header.TFrame')
        header.pack(fill='x')
        mark = tk.Canvas(header, width=18, height=18, bg='#0e1012', highlightthickness=0)
        mark.pack(side='left', padx=(0, 6))
        mark.create_oval(2, 2, 15, 15, outline='#a6ded0', width=2)
        mark.create_oval(7, 7, 10, 10, fill='#eef3f5', outline='')
        ttk.Label(header, text='SENTINEL', style='Brand.TLabel').pack(side='left')
        for label, command in [('Local utilities', self.open_local_utilities),
                               ('Dependencies', self.open_dependencies), ('Security tools', self.open_network),
                               ('New assessment', self.open_guided)]:
            ttk.Button(header, text=label, command=command).pack(side='right', padx=(6, 0))

        workspace = ttk.Frame(self, padding=(12, 12), style='Canvas.TFrame')
        workspace.pack(fill='both', expand=True)
        self.build_overview(workspace)
        self.build_assessment_form(workspace)
        self.build_results(workspace)
        if self.project.get() in self.project_box.cget('values'):
            self.load_history()
        self.poll_timer = self.after(100, self.poll)

    def build_assessment_form(self, parent):
        form = ttk.Frame(parent, padding=(14, 10), style='Card.TFrame')
        form.pack(fill='x', pady=(0, 9))
        form.columnconfigure(1, weight=1)
        for column, label in enumerate(('Project', 'Website URL', 'Optional DNS domain')):
            ttk.Label(form, text=label, style='Muted.TLabel').grid(row=0, column=column, sticky='w', padx=(0, 8))
        self.project_box = ttk.Combobox(form, textvariable=self.project, values=self.store.projects(), width=20)
        self.project_box.grid(row=1, column=0, sticky='ew', padx=(0, 8), pady=(3, 0))
        self.project_box.bind('<<ComboboxSelected>>', lambda event: self.load_history())
        ttk.Entry(form, textvariable=self.url).grid(row=1, column=1, sticky='ew', padx=(0, 8), pady=(3, 0))
        ttk.Entry(form, textvariable=self.dns, width=23).grid(row=1, column=2, sticky='ew', padx=(0, 8), pady=(3, 0))
        self.run_btn = ttk.Button(form, text='Run assessment', command=self.run, style='Primary.TButton')
        self.run_btn.grid(row=1, column=3, sticky='ew', padx=(0, 6), pady=(3, 0))
        self.stop_btn = ttk.Button(form, text='Stop', command=self.stop, state='disabled')
        self.stop_btn.grid(row=1, column=4, sticky='ew', pady=(3, 0))
        self.auth_check = ttk.Checkbutton(form, text='I have explicit permission to assess this URL and any DNS domain entered.',
                                          variable=self.auth)
        self.auth_check.grid(row=2, column=0, columnspan=5, sticky='w', pady=(8, 0))
        ttk.Label(form, text='Assessment depth', style='Muted.TLabel').grid(row=3, column=0, sticky='w', pady=(6, 0))
        ttk.Combobox(form, textvariable=self.assessment_profile, values=('Quick', 'Standard'),
                     width=12, state='readonly').grid(row=3, column=1, sticky='w', pady=(6, 0))
        ttk.Label(form, text='Standard adds same-endpoint TLS 1.2/1.3 verification.', style='Muted.TLabel').grid(
            row=3, column=2, columnspan=3, sticky='w', pady=(6, 0))
        watch_variables(self, (self.url, self.dns, self.assessment_profile), lambda *_: self.auth.set(False))

    def build_overview(self, parent):
        overview = ttk.Frame(parent, style='Canvas.TFrame')
        overview.pack(fill='x')
        metrics = [('Project assessments', self.assessment_count), ('Findings', self.observation_count),
                   ('Highest severity', self.highest), ('Selected assessment', self.summary)]
        for column, (label, value) in enumerate(metrics):
            overview.columnconfigure(column, weight=2 if column == 3 else 1, uniform='metrics')
            card = ttk.Frame(overview, padding=(14, 10), style='Card.TFrame')
            card.grid(row=0, column=column, sticky='nsew', padx=(0, 0 if column == 3 else 8))
            ttk.Label(card, text=label, style='Muted.TLabel').pack(anchor='w')
            ttk.Label(card, textvariable=value, style='Title.TLabel').pack(anchor='w', pady=(3, 0))
        ttk.Label(parent, textvariable=self.status, style='Canvas.TLabel', anchor='center').pack(fill='x', pady=(8, 4))
        track = ttk.Frame(parent, height=4)
        track.pack(fill='x', pady=(0, 12))
        self.progress = ttk.Progressbar(track, style='Scan.Horizontal.TProgressbar')
        self.progress.place(relwidth=1, relheight=1)

    def build_results(self, parent):
        panes = ttk.Panedwindow(parent, orient='horizontal')
        panes.pack(fill='both', expand=True)
        left = ttk.Frame(panes, padding=12, width=440, style='Card.TFrame')
        middle = ttk.Frame(panes, padding=12, width=210, style='Card.TFrame')
        right = ttk.Frame(panes, padding=12, width=350, style='Card.TFrame')
        for panel, weight in [(left, 5), (middle, 2), (right, 4)]:
            panes.add(panel, weight=weight)

        ttk.Label(left, text='Findings', style='Title.TLabel').pack(anchor='w', pady=(0, 8))
        findings = ttk.Frame(left)
        findings.pack(fill='both', expand=True)
        ttk.Label(middle, text='SELECTED FINDING', style='Section.TLabel').pack(anchor='w')
        ttk.Label(middle, textvariable=self.selection_title, style='Title.TLabel',
                  wraplength=180, justify='left').pack(anchor='w', pady=(10, 5))
        ttk.Label(middle, textvariable=self.selection_meta, style='Muted.TLabel',
                  wraplength=175, justify='left').pack(anchor='w')
        actions = ttk.Frame(middle)
        actions.pack(side='bottom', fill='x')
        ttk.Label(actions, text='ASSESSMENT ACTIONS', style='Section.TLabel').pack(anchor='w', pady=(0, 8))
        self.result_buttons = []
        for label, command in [('Compare previous', self.diff), ('Export HTML', self.export),
                               ('Export JSON', self.export_json)]:
            button = ttk.Button(actions, text=label, command=command, state='disabled')
            button.pack(fill='x', pady=(0, 5))
            self.result_buttons.append(button)

        ttk.Label(right, text='Evidence & remediation', style='Title.TLabel').pack(anchor='w', pady=(0, 7))
        detail = ttk.Frame(right)
        detail.pack(fill='both', expand=True)
        heading = ttk.Frame(right)
        heading.pack(fill='x', pady=(12, 5))
        ttk.Label(heading, text='Project history', style='Title.TLabel').pack(side='left')
        ttk.Button(heading, text='Load history', command=self.load_history).pack(side='right')
        history = ttk.Frame(right)
        history.pack(fill='both', expand=True)

        self.history = ttk.Treeview(history, columns=('time', 'status'), show='headings', height=8)
        self.history.heading('time', text='UTC time')
        self.history.heading('status', text='Status')
        self.history.column('time', width=135, minwidth=80)
        self.history.column('status', width=76, minwidth=50)
        scrollable(history, self.history)
        self.history.bind('<<TreeviewSelect>>', self.history_selected)

        self.findings = ttk.Treeview(findings, columns=('title', 'severity'), show='headings', height=8)
        self.findings.heading('severity', text='Severity')
        self.findings.heading('title', text='Finding')
        self.findings.column('severity', width=78, minwidth=63, stretch=False)
        self.findings.column('title', width=235, minwidth=90)
        for severity, color in SEVERITY_COLORS.items():
            self.findings.tag_configure(severity, foreground=color)
        scrollable(findings, self.findings)
        self.findings.bind('<<TreeviewSelect>>', self.finding_selected)

        self.detail = detail_box(detail)
        self.detail.configure(width=26)
        scrollable(detail, self.detail)
        self.set_detail('Run an assessment or open project history to inspect findings.')

    def open_guided(self):
        from .guided_window import GuidedWindow
        window = self.children.get('guided_assessment')
        if window is None:
            window = GuidedWindow(self)
        else:
            window.deiconify()
            window.lift()
        return window

    def open_local_utilities(self):
        from .local_window import LocalUtilitiesWindow
        window = self.children.get('local_utilities')
        if window is None:
            window = LocalUtilitiesWindow(self, name='local_utilities')
        else:
            window.deiconify()
            window.lift()
        return window

    def open_network(self):
        from .tools_window import ToolsWindow
        ToolsWindow(self)
    def open_dependencies(self):
        from .dependency_window import DependencyWindow
        DependencyWindow(self)
    def set_detail(self,text):
        self.detail.configure(state='normal'); self.detail.delete('1.0','end'); self.detail.insert('1.0',text); self.detail.configure(state='disabled')
    def run(self):
        if self.busy:return
        try:
            if not self.auth.get():raise PermissionError('Confirm explicit permission before testing.')
            profile = self.assessment_profile.get()
            if profile not in ('Quick', 'Standard'): raise ValueError('Unknown assessment profile.')
            operation = standard_scan if profile == 'Standard' else scan
            target=Target.parse(self.url.get()); dns=domain_name(self.dns.get()) if self.dns.get().strip() else ''; pid=self.store.project(self.project.get()); name=self.project.get().strip()
        except (ValueError,PermissionError) as e:messagebox.showerror('Cannot start',str(e));return
        self.progress.configure(mode='indeterminate')
        self.progress.start(18)
        self.busy=True; self.cancel_event=Event(); self.stop_btn.configure(state='normal'); self.run_btn.configure(state='disabled'); self.status.set('Assessing authorized URL…'); self.auth.set(False)
        cancel, queue = self.cancel_event, self.queue
        try:
            self.job = self.orchestrator.submit(
                lambda: operation(target.url, authorized=True, cancel=cancel, dns_domain=dns).to_dict(),
                lambda result, error: queue.put((pid, name, result, error)), cancel)
            self.status.set('Queued; one check runs at a time.')
        except RuntimeError as exc:
            self.queue.put((pid, name, None, str(exc)))
    def stop(self):
        if self.busy:
            self.cancel_event.set(); self.stop_btn.configure(state='disabled'); self.status.set('Stopping after current bounded operation…')
    def poll(self):
        if self.busy and hasattr(self, 'job') and not self.cancel_event.is_set():
            self.status.set(self.job.state.capitalize() + ' • authorized assessment')
        try:
            pid,name,result,error=self.queue.get_nowait()
            self.progress.stop()
            self.progress.configure(mode='determinate', value=0 if error else 100)
            self.busy=False; self.stop_btn.configure(state='disabled'); self.run_btn.configure(state='normal')
            if error:self.status.set('Assessment error: '+error)
            else:
                sid=self.store.save(pid,result); self.project.set(name); self.project_box.configure(values=self.store.projects()); self.load_history(sid); self.status.set('Assessment '+result['status']+' • Saved locally.')
        except Empty:pass
        except Exception as e:self.status.set('Local storage/UI error: '+type(e).__name__)
        self.poll_timer = self.after(100,self.poll)
    def load_history(self,select_id=None):
        if self.busy:return
        try:pid=self.store.project(self.project.get())
        except ValueError as e:messagebox.showerror('Project',str(e));return
        self.project_box.configure(values=self.store.projects()); self.records=self.store.history(pid); self.history.delete(*self.history.get_children())
        self.assessment_count.set(str(len(self.records)))
        for sid,r in self.records:self.history.insert('','end',iid=str(sid),values=(r['started'][:19].replace('T',' '),r['status']))
        if self.records:
            sid=select_id or self.records[0][0]; self.history.selection_set(str(sid)); self.show(dict(self.records)[sid],sid)
        else:
            self.reset_inspector(False)
            self.current=None; self.current_id=None; self.summary.set('No assessment selected'); self.observation_count.set('—'); self.findings.delete(*self.findings.get_children()); self.set_detail('Run an authorized assessment to begin.')
    def history_selected(self,event=None):
        s=self.history.selection()
        if s and int(s[0]) in dict(self.records):self.show(dict(self.records)[int(s[0])],int(s[0]))
    def reset_inspector(self, has_assessment):
        self.highest.set('—')
        self.selection_title.set('Select a finding')
        self.selection_meta.set('Choose a row to inspect its evidence.')
        for button in self.result_buttons:
            button.state(['!disabled'] if has_assessment else ['disabled'])

    def show(self,r,sid):
        self.current = r
        self.current_id = sid
        self.findings.delete(*self.findings.get_children())
        self.reset_inspector(True)
        levels = {f['severity'].lower() for f in r['findings']}
        self.highest.set(next((level.title() for level in SEVERITY_COLORS if level in levels), '—'))
        coverage = r.get('coverage', {})
        connection = [coverage['tool']] if coverage.get('tool') else [
            f"HTTP {r['http_status']}" if r.get('http_status') else '', r.get('tls')]
        self.summary.set(' · '.join(filter(None, [r['status'].capitalize(), *connection])))
        self.observation_count.set(str(len(r['findings'])))
        for index, finding in enumerate(r['findings']):
            severity = finding['severity']
            self.findings.insert('', 'end', iid=str(index), values=(finding['title'], severity.upper()),
                                 tags=(severity.lower(),))
        self.set_detail(r['target']+'\n\nCoverage: '+json.dumps(r.get('coverage',{'profile':'legacy v0.1'}),ensure_ascii=False)+'\n\n'+(r['error'] or 'Select a finding for evidence and remediation. These are configuration observations, not verified exploits.'))
    def finding_selected(self,event=None):
        s=self.findings.selection()
        if s and self.current:
            f=self.current['findings'][int(s[0])]
            self.selection_title.set(f['title'])
            self.selection_meta.set(' · '.join(filter(None, [f['severity'].title(), f.get('source')])))
            self.set_detail(f"{f['title']}\n\nOBSERVED EVIDENCE\n{f['evidence']}\n\nREMEDIATION\n{f['remediation']}")
    def export(self):
        if not self.current:messagebox.showinfo('Export','Select an assessment first.');return
        p=filedialog.asksaveasfilename(defaultextension='.html',filetypes=[('HTML report','*.html')],initialfile='sentinel-report.html')
        if p:
            try:Path(p).write_text(html_report(self.current),encoding='utf-8'); self.status.set('Report exported.')
            except OSError:messagebox.showerror('Export','Could not write the selected file.')
    def export_json(self):
        if not self.current:messagebox.showinfo('Export','Select an assessment first.');return
        p=filedialog.asksaveasfilename(defaultextension='.json',filetypes=[('JSON report','*.json')],initialfile='sentinel-report.json')
        if p:
            try:Path(p).write_text(json.dumps(self.current,indent=2,ensure_ascii=False),encoding='utf-8'); self.status.set('JSON report exported.')
            except OSError:messagebox.showerror('Export','Could not write the selected file.')
    def diff(self):
        if not self.current:return
        prev=next((r for sid,r in self.records if sid<self.current_id and r['target']==self.current['target'] and r.get('profile','web-v1')==self.current.get('profile','web-v1') and r.get('dns_domain','')==self.current.get('dns_domain','')),None)
        if not prev:messagebox.showinfo('Comparison','No earlier assessment of this exact URL.');return
        d=compare(prev,self.current)
        if not d['comparable']:self.set_detail('Assessment results are not comparable (incomplete checks, changed scope, profile or HTTP status).');return
        self.set_detail('COMPARISON\n\nNew: '+(', '.join(d['new']) or 'None')+'\nStill observed: '+(', '.join(d['still_present']) or 'None')+'\nNot observed on retest: '+(', '.join(d['not_observed']) or 'None')+'\n\nNot observed does not prove a vulnerability is resolved. Confirm changes in context.')
    def close(self):
        if self.busy and not messagebox.askyesno('Exit','An assessment is running. Exit without saving its result?'):return
        self.cancel_event.set(); self.orchestrator.shutdown(); self.store.close(); self.destroy()

def main():
    import os
    from .logging_setup import configure
    try:
        configure(Path(os.environ.get('LOCALAPPDATA') or Path.home()/'.local'/'share')/'Sentinel'/'events.jsonl')
    except OSError:
        pass  # A read-only log directory must not stop assessment or history access.
    App().mainloop()
