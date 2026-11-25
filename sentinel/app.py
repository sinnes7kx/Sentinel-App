from .ui_lifecycle import watch_poll, watch_variables
from .desktop_theme import SEVERITY_COLORS, configure_theme, detail_box, scrollable
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from threading import Event
from .orchestration import for_app
from queue import Queue, Empty
from pathlib import Path
from .engine import Target, scan, compare
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
        self.geometry('1180x740')
        self.minsize(910, 600)
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
        self.auth = tk.BooleanVar()
        self.status = tk.StringVar(value='Ready')
        self.summary = tk.StringVar(value='No assessment selected')
        self.observation_count = tk.StringVar(value='—')
        self.assessment_count = tk.StringVar(value='0')

        header = ttk.Frame(self, style='Canvas.TFrame')
        header.pack(fill='x', padx=18, pady=(13, 10))
        ttk.Label(header, text='Sentinel', style='Brand.TLabel').pack(side='left')
        ttk.Button(header, text='Local utilities', command=self.open_local_utilities).pack(side='right')
        ttk.Button(header, text='Dependencies', command=self.open_dependencies).pack(side='right', padx=7)
        ttk.Button(header, text='Security tools', command=self.open_network).pack(side='right')

        workspace = ttk.Frame(self, style='Canvas.TFrame')
        workspace.pack(fill='both', expand=True, padx=18)
        self.build_assessment_form(workspace)
        self.build_results(workspace)
        ttk.Label(self, textvariable=self.status, style='Canvas.TLabel').pack(fill='x', padx=18, pady=9)
        if self.project.get() in self.project_box.cget('values'):
            self.load_history()
        self.poll_timer = self.after(100, self.poll)

    def build_assessment_form(self, parent):
        form = ttk.Frame(parent, padding=(12, 9))
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
        watch_variables(self, (self.url, self.dns), lambda *_: self.auth.set(False))

    def build_results(self, parent):
        overview = ttk.Frame(parent, style='Canvas.TFrame')
        overview.pack(fill='x', pady=(0, 9))
        metrics = [('Selected assessment', self.summary), ('Observations', self.observation_count),
                   ('Project assessments', self.assessment_count)]
        for column, (label, value) in enumerate(metrics):
            overview.columnconfigure(column, weight=2 if column == 0 else 1)
            card = ttk.Frame(overview, padding=(12, 7))
            card.grid(row=0, column=column, sticky='nsew', padx=(0, 8 if column < 2 else 0))
            ttk.Label(card, text=label, style='Muted.TLabel').pack(anchor='w')
            ttk.Label(card, textvariable=value, style='Title.TLabel').pack(anchor='w', pady=(2, 0))

        actions = ttk.Frame(parent, padding=(7, 5))
        actions.pack(fill='x', pady=(0, 9))
        for label, command in [('Load history', self.load_history), ('Compare previous', self.diff),
                               ('Export HTML', self.export), ('Export JSON', self.export_json)]:
            ttk.Button(actions, text=label, command=command).pack(side='left', padx=(0, 5))

        panes = ttk.Panedwindow(parent, orient='horizontal')
        panes.pack(fill='both', expand=True)
        panels = []
        for label, weight in [('History', 1), ('Findings', 3), ('Evidence & remediation', 2)]:
            panel = ttk.Frame(panes, padding=8)
            panes.add(panel, weight=weight)
            ttk.Label(panel, text=label, style='Title.TLabel').pack(anchor='w', pady=(0, 7))
            body = ttk.Frame(panel)
            body.pack(fill='both', expand=True)
            panels.append(body)
        history, findings, detail = panels

        self.history = ttk.Treeview(history, columns=('time', 'status'), show='headings', height=8)
        self.history.heading('time', text='UTC time')
        self.history.heading('status', text='Status')
        self.history.column('time', width=135, minwidth=80)
        self.history.column('status', width=76, minwidth=50)
        scrollable(history, self.history)
        self.history.bind('<<TreeviewSelect>>', self.history_selected)

        self.findings = ttk.Treeview(findings, columns=('severity', 'title'), show='headings', height=8)
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
            target=Target.parse(self.url.get()); dns=domain_name(self.dns.get()) if self.dns.get().strip() else ''; pid=self.store.project(self.project.get()); name=self.project.get().strip()
        except (ValueError,PermissionError) as e:messagebox.showerror('Cannot start',str(e));return
        self.busy=True; self.cancel_event=Event(); self.stop_btn.configure(state='normal'); self.run_btn.configure(state='disabled'); self.status.set('Assessing authorized URL…'); self.auth.set(False)
        cancel, queue = self.cancel_event, self.queue
        try:
            self.job = self.orchestrator.submit(
                lambda: scan(target.url, authorized=True, cancel=cancel, dns_domain=dns).to_dict(),
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
            pid,name,result,error=self.queue.get_nowait(); self.busy=False; self.stop_btn.configure(state='disabled'); self.run_btn.configure(state='normal')
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
            self.current=None; self.current_id=None; self.summary.set('No assessment selected'); self.observation_count.set('—'); self.findings.delete(*self.findings.get_children()); self.set_detail('Run an authorized assessment to begin.')
    def history_selected(self,event=None):
        s=self.history.selection()
        if s and int(s[0]) in dict(self.records):self.show(dict(self.records)[int(s[0])],int(s[0]))
    def show(self,r,sid):
        self.current = r
        self.current_id = sid
        self.findings.delete(*self.findings.get_children())
        coverage = r.get('coverage', {})
        connection = [coverage['tool']] if coverage.get('tool') else [
            f"HTTP {r['http_status']}" if r.get('http_status') else '', r.get('tls')]
        self.summary.set(' · '.join(filter(None, [r['status'].capitalize(), *connection])))
        self.observation_count.set(str(len(r['findings'])))
        for index, finding in enumerate(r['findings']):
            severity = finding['severity']
            self.findings.insert('', 'end', iid=str(index), values=(severity.upper(), finding['title']),
                                 tags=(severity.lower(),))
        self.set_detail(r['target']+'\n\nCoverage: '+json.dumps(r.get('coverage',{'profile':'legacy v0.1'}),ensure_ascii=False)+'\n\n'+(r['error'] or 'Select a finding for evidence and remediation. These are configuration observations, not verified exploits.'))
    def finding_selected(self,event=None):
        s=self.findings.selection()
        if s and self.current:
            f=self.current['findings'][int(s[0])]; self.set_detail(f"{f['title']}\n\nOBSERVED EVIDENCE\n{f['evidence']}\n\nREMEDIATION\n{f['remediation']}")
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
