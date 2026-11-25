from .ui_lifecycle import watch_poll, watch_variables
from .scan_confirmation import confirm_website
from .desktop_theme import SEVERITY_COLORS, configure_theme, detail_box, scrollable
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from threading import Event
from .orchestration import for_app
from queue import Queue, Empty
from pathlib import Path
from .engine import Target, scan, compare
from .standard_assessment import standard_scan
from .extended_assessment import extended_scan
from .store import Store, REMEDIATION_STATES
from .dnscheck import domain_name
import json
import os
from .report import html_report
from .finding_views import finding_views, finding_detail, findings_summary
from .retest_review import review, review_text
from .remediation_checklist import checklist, counts, filtered, FILTERS


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
        self.geometry('1160x700')
        self.minsize(1000, 650)
        configure_theme(self)
        self.orchestrator = for_app(self)
        self.store = Store()
        self.queue = Queue()
        self.current = None
        self.current_id = None
        self.history_project_id = None
        self.records = []
        self.busy = False
        self.cancel_event = Event()
        self.protocol('WM_DELETE_WINDOW', self.close)

        self.project = tk.StringVar(value='My website')
        self.url = tk.StringVar(value='https://')
        self.dns = tk.StringVar()
        self.assessment_profile = tk.StringVar(value='Quick')
        self.confirming = False
        self.status = tk.StringVar(value='Ready')
        self.summary = tk.StringVar(value='No assessment selected')
        self.observation_count = tk.StringVar(value='—')
        self.assessment_count = tk.StringVar(value='0')

        self.highest = tk.StringVar(value='—')
        self.selection_title = tk.StringVar(value='Select a finding')
        self.selection_meta = tk.StringVar(value='Choose a row to inspect its evidence.')
        self.remediation_state = tk.StringVar(value='Open')
        self.remediation_updated = tk.StringVar(value='')
        shell = ttk.Frame(self, style='Canvas.TFrame')
        shell.pack(fill='both', expand=True)
        self.navigation = ttk.Frame(shell, padding=(10, 12), style='Header.TFrame', width=168)
        self.navigation.pack(side='left', fill='y')
        ttk.Label(self.navigation, text='SENTINEL', style='Brand.TLabel').pack(anchor='w', pady=(0, 4))
        ttk.Label(self.navigation, text='Security workspace', style='NavCaption.TLabel').pack(anchor='w', pady=(0, 12))
        self.nav_buttons = {}
        for label, command, style in (
            ('New assessment', self.open_guided, 'Primary.TButton'),
            ('Findings', lambda: self.show_workspace('findings'), 'Nav.TButton'),
            ('Remediation', lambda: self.show_workspace('remediation'), 'Nav.TButton'),
            ('Project history', lambda: self.show_workspace('history'), 'Nav.TButton'),
            ('Security tools', self.open_network, 'Nav.TButton'),
            ('Dependencies', self.open_dependencies, 'Nav.TButton'),
            ('CVE review', self.open_cve_review, 'Nav.TButton'),
            ('Local utilities', self.open_local_utilities, 'Nav.TButton'),
        ):
            button = ttk.Button(self.navigation, text=label, command=command, style=style)
            button.pack(fill='x', pady=(0, 3))
            self.nav_buttons[label] = button
        if os.name == 'nt':
            button = ttk.Button(self.navigation, text='Tool setup', command=self.open_tool_setup, style='Nav.TButton')
            button.pack(fill='x', pady=(0, 3))
            self.nav_buttons['Tool setup'] = button
        ttk.Label(self.navigation, text='LOCAL WORKSPACE', style='NavCaption.TLabel').pack(side='bottom', anchor='w')
        workspace = ttk.Frame(shell, padding=(12, 8), style='Canvas.TFrame')
        workspace.pack(side='left', fill='both', expand=True)
        ttk.Label(workspace, text='Website assessment', style='WorkspaceTitle.TLabel').pack(anchor='w')
        ttk.Label(workspace, text='Assess an authorized website, inspect evidence and track improvements.',
                  style='Canvas.TLabel', wraplength=760).pack(anchor='w', pady=(2, 12))
        self.build_overview(workspace)
        self.build_assessment_form(workspace)
        self.build_results(workspace)
        if self.project.get() in self.project_box.cget('values'):
            self.load_history()
        self.poll_timer = self.after(100, self.poll)

    def build_assessment_form(self, parent):
        form = ttk.Frame(parent, padding=(10, 7), style='Card.TFrame')
        form.pack(fill='x', pady=(0, 6))
        form.columnconfigure(1, weight=1)
        ttk.Label(form, text='Project', style='Muted.TLabel').grid(row=0, column=0, sticky='w', padx=(0, 8))
        ttk.Label(form, text='Website URL', style='Muted.TLabel').grid(row=0, column=1, sticky='w')
        self.project_box = ttk.Combobox(form, textvariable=self.project, values=self.store.projects(), width=17)
        self.project_box.grid(row=1, column=0, sticky='ew', padx=(0, 8), pady=(3, 0))
        self.project_box.bind('<<ComboboxSelected>>', lambda event: self.load_history())
        self.target_entry = ttk.Entry(form, textvariable=self.url)
        self.target_entry.grid(row=1, column=1, sticky='ew', padx=(0, 8), pady=(3, 0))
        self.run_btn = ttk.Button(form, text='Run assessment', command=self.run, style='Primary.TButton')
        self.run_btn.grid(row=1, column=2, sticky='ew', padx=(0, 6), pady=(3, 0))
        self.stop_btn = ttk.Button(form, text='Stop', command=self.stop, state='disabled')
        self.stop_btn.grid(row=1, column=3, sticky='ew', pady=(3, 0))
        ttk.Label(form, text='Assessment depth', style='Muted.TLabel').grid(row=2, column=0, sticky='w', pady=(9, 0))
        ttk.Label(form, text='Optional DNS domain', style='Muted.TLabel').grid(row=2, column=1, sticky='w', pady=(9, 0))
        ttk.Combobox(form, textvariable=self.assessment_profile, values=('Quick', 'Standard', 'Extended'),
                     width=12, state='readonly').grid(row=3, column=0, sticky='ew', padx=(0, 8))
        ttk.Entry(form, textvariable=self.dns).grid(row=3, column=1, sticky='ew', padx=(0, 8))
        ttk.Label(form, text='Extended adds cross-origin checks.', style='Muted.TLabel',
                  wraplength=170).grid(row=3, column=2, columnspan=2, sticky='w')

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
            metric = ttk.Label(card, textvariable=value, style='Title.TLabel')
            metric.pack(anchor='w', pady=(3, 0))
            if value is self.highest:
                self.highest_label = metric
        ttk.Label(parent, textvariable=self.status, style='Canvas.TLabel', anchor='center').pack(fill='x', pady=(8, 4))
        track = ttk.Frame(parent, height=4)
        track.pack(fill='x', pady=(0, 12))
        self.progress = ttk.Progressbar(track, style='Scan.Horizontal.TProgressbar')
        self.progress.place(relwidth=1, relheight=1)

    def build_results(self, parent):
        panes = ttk.Panedwindow(parent, orient='horizontal')
        panes.pack(fill='both', expand=True)
        left = ttk.Frame(panes, padding=10, style='Card.TFrame')
        right = ttk.Frame(panes, padding=10, style='Card.TFrame')
        panes.add(left, weight=4)
        panes.add(right, weight=5)
        self.workspace_tabs = ttk.Notebook(left)
        self.workspace_tabs.pack(fill='both', expand=True)
        self.findings_page = ttk.Frame(self.workspace_tabs, padding=6)
        self.history_page = ttk.Frame(self.workspace_tabs, padding=6)
        self.workspace_tabs.add(self.findings_page, text='Findings')
        self.workspace_tabs.add(self.history_page, text='History')
        self.remediation_page = ttk.Frame(self.workspace_tabs, padding=6)
        self.workspace_tabs.add(self.remediation_page, text='Remediation')
        self.build_checklist()
        self.workspace_tabs.bind('<<NotebookTabChanged>>', self.workspace_tab_changed)

        self.findings = ttk.Treeview(self.findings_page, columns=('title', 'severity'), show='headings', height=8)
        self.findings.heading('severity', text='Risk')
        self.findings.heading('title', text='Finding')
        self.findings.column('severity', width=72, minwidth=60, stretch=False)
        self.findings.column('title', width=225, minwidth=90)
        for severity, color in SEVERITY_COLORS.items():
            self.findings.tag_configure(severity, foreground=color)
        scrollable(self.findings_page, self.findings)
        self.findings.bind('<<TreeviewSelect>>', self.finding_selected)

        history_actions = ttk.Frame(self.history_page)
        history_actions.pack(fill='x', pady=(0, 6))
        ttk.Button(history_actions, text='Refresh', command=self.load_history).pack(side='left')
        ttk.Button(history_actions, text='View findings', command=lambda: self.show_workspace('findings')).pack(side='right')
        history = ttk.Frame(self.history_page)
        history.pack(fill='both', expand=True)
        self.history = ttk.Treeview(history, columns=('time', 'status'), show='headings', height=8)
        self.history.heading('time', text='UTC time')
        self.history.heading('status', text='Status')
        self.history.column('time', width=150, minwidth=100)
        self.history.column('status', width=80, minwidth=60)
        scrollable(history, self.history)
        self.history.bind('<<TreeviewSelect>>', self.history_selected)
        self.history.bind('<Double-1>', lambda event: self.show_workspace('findings'))

        ttk.Label(right, textvariable=self.selection_title, style='Title.TLabel',
                  wraplength=390, justify='left').pack(anchor='w', pady=(0, 3))
        ttk.Label(right, textvariable=self.selection_meta, style='Muted.TLabel',
                  wraplength=390, justify='left').pack(anchor='w', pady=(0, 7))
        controls = ttk.Frame(right)
        controls.pack(side='bottom', fill='x')
        ttk.Label(controls, text='Manual remediation', style='Muted.TLabel').pack(anchor='w', pady=(6, 2))
        status_row = ttk.Frame(controls)
        status_row.pack(fill='x')
        self.remediation_box = ttk.Combobox(status_row, values=REMEDIATION_STATES,
                                           textvariable=self.remediation_state, state='disabled', width=17)
        self.remediation_box.pack(side='left', fill='x', expand=True)
        self.remediation_button = ttk.Button(status_row, text='Save status', command=self.save_remediation,
                                             state='disabled')
        self.remediation_button.pack(side='left', padx=(6, 0))
        ttk.Label(controls, textvariable=self.remediation_updated, style='Muted.TLabel',
                  wraplength=390).pack(anchor='w', pady=3)
        actions = ttk.Frame(controls)
        actions.pack(fill='x', pady=(5, 0))
        self.result_buttons = []
        for i, (label, command) in enumerate((('Compare previous', self.diff), ('Retest evidence', self.retest_evidence),
                                             ('Export HTML', self.export), ('Export JSON', self.export_json))):
            button = ttk.Button(actions, text=label, command=command, state='disabled')
            button.grid(row=i // 2, column=i % 2, sticky='ew', padx=2, pady=2)
            actions.columnconfigure(i % 2, weight=1)
            self.result_buttons.append(button)
        detail = ttk.Frame(right)
        detail.pack(fill='both', expand=True)
        self.detail = detail_box(detail, height=6)
        self.detail.configure(width=26)
        scrollable(detail, self.detail)
        self.set_detail('Run an assessment or open project history to inspect findings.')

    def build_checklist(self):
        page = self.remediation_page
        self.checklist_filter = tk.StringVar(value='All')
        self.checklist_summary = tk.StringVar(value='Select a saved assessment.')
        toolbar = ttk.Frame(page)
        toolbar.pack(fill='x', pady=(0, 4))
        ttk.Label(toolbar, text='Status').pack(side='left', padx=(0, 4))
        select = ttk.Combobox(toolbar, textvariable=self.checklist_filter, values=FILTERS,
                              state='readonly', width=17)
        select.pack(side='left', fill='x', expand=True)
        select.bind('<<ComboboxSelected>>', lambda event: self.refresh_checklist())
        ttk.Label(page, textvariable=self.checklist_summary, wraplength=270,
                  justify='left', style='Muted.TLabel').pack(anchor='w', pady=(0, 4))
        ttk.Label(page, text='Manual progress only; retest to verify.',
                  style='Muted.TLabel').pack(anchor='w', pady=(0, 3))
        table = ttk.Frame(page)
        table.pack(fill='both', expand=True)
        self.checklist_tree = ttk.Treeview(table, columns=('risk', 'title', 'state'),
                                          show='headings', selectmode='browse', height=7)
        for column, title, width in (('risk', 'Risk', 65), ('title', 'Finding', 120), ('state', 'Status', 120)):
            self.checklist_tree.heading(column, text=title)
            self.checklist_tree.column(column, width=width, minwidth=45, stretch=column != 'risk')
        for severity, color in SEVERITY_COLORS.items():
            self.checklist_tree.tag_configure(severity, foreground=color)
        scrollable(table, self.checklist_tree)
        self.checklist_tree.bind('<<TreeviewSelect>>', self.checklist_selected)

    def refresh_checklist(self):
        tree = self.checklist_tree
        selected = tree.selection()
        tree.delete(*tree.get_children())
        rows = checklist(self.current, getattr(self, 'review_states', {}))
        totals = counts(rows)
        self.checklist_summary.set(
            f"{totals['Open']} open · {totals['Investigating']} investigating\n"
            f"{totals['Remediation applied']} applied · {totals['Retest required']} retest required"
            if self.current is not None else 'Select a saved assessment.')
        for row in filtered(rows, self.checklist_filter.get()):
            title = row.title + (f' ({row.occurrences})' if row.occurrences > 1 else '')
            tree.insert('', 'end', iid=str(row.index), values=(row.severity.upper(), title, row.state),
                        tags=(row.severity.lower(),))
        if selected and tree.exists(selected[0]):
            tree.selection_set(selected[0])

    def checklist_selected(self, _event=None):
        if self.workspace_tabs.select() != str(self.remediation_page):
            return
        selected = self.checklist_tree.selection()
        if selected and self.findings.exists(selected[0]):
            self.findings.selection_set(selected[0])
            self.finding_selected()
        else:
            self.findings.selection_remove(*self.findings.selection())
            self.selection_title.set('Select a finding')
            self.selection_meta.set('Choose a checklist row to inspect evidence.')
            self.remediation_updated.set('')
            self.set_detail('Select a remediation item to review the evidence and recommended fix.')
            self.finding_selected()

    def workspace_tab_changed(self, _event=None):
        if self.workspace_tabs.select() == str(self.remediation_page):
            self.checklist_selected()

    def show_workspace(self, page):
        self.workspace_tabs.select({'history': self.history_page, 'remediation': self.remediation_page}.get(page, self.findings_page))
        if page == 'remediation':
            self.refresh_checklist()
            self.checklist_selected()

    def open_guided(self):
        from .guided_window import GuidedWindow
        window = self.children.get('guided_assessment')
        if window is None:
            window = GuidedWindow(self)
        else:
            window.deiconify()
            window.lift()
        return window

    def open_cve_review(self):
        from .cve_window import CVEWindow
        window = self.children.get('cve_review')
        if window is None:
            window = CVEWindow(self)
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

    def open_tool_setup(self):
        return self.open_network().open_tool_setup()

    def open_network(self):
        from .tools_window import ToolsWindow
        window = self.children.get('security_tools')
        if window is None:
            window = ToolsWindow(self, name='security_tools')
        else:
            window.deiconify()
            window.lift()
        return window
    def open_dependencies(self):
        from .dependency_window import DependencyWindow
        DependencyWindow(self)
    def set_detail(self,text):
        self.detail.configure(state='normal'); self.detail.delete('1.0','end'); self.detail.insert('1.0',text); self.detail.configure(state='disabled')
    def run(self):
        if self.busy or self.confirming:return
        try:
            profile = self.assessment_profile.get()
            if profile not in ('Quick', 'Standard', 'Extended'): raise ValueError('Unknown assessment profile.')
            operation = {'Quick': scan, 'Standard': standard_scan, 'Extended': extended_scan}[profile]
            target=Target.parse(self.url.get()); dns=domain_name(self.dns.get()) if self.dns.get().strip() else ''; name=self.project.get().strip()
            self.confirming = True
            try:
                approved = confirm_website(self, target.url, profile, dns)
            finally:
                self.confirming = False
            if not approved: return
            pid=self.store.project(name)
        except (ValueError,PermissionError) as e:messagebox.showerror('Cannot start',str(e));return
        self.progress.configure(mode='indeterminate')
        self.progress.start(18)
        self.busy=True; self.cancel_event=Event(); self.stop_btn.configure(state='normal'); self.run_btn.configure(state='disabled'); self.status.set('Assessing authorized URL…')
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
                sid=self.store.save(pid,result); self.project.set(name); self.project_box.configure(values=self.store.projects()); self.load_history(sid); self.show_workspace('findings'); self.status.set('Assessment '+result['status']+' • Saved locally.')
        except Empty:pass
        except Exception as e:self.status.set('Local storage/UI error: '+type(e).__name__)
        self.poll_timer = self.after(100,self.poll)
    def load_history(self,select_id=None):
        if self.busy:return
        try:pid=self.store.project(self.project.get())
        except ValueError as e:messagebox.showerror('Project',str(e));return
        self.history_project_id = pid
        self.project_box.configure(values=self.store.projects()); self.records=self.store.history(pid); self.history.delete(*self.history.get_children())
        self.assessment_count.set(str(len(self.records)))
        for sid,r in self.records:self.history.insert('','end',iid=str(sid),values=(r['started'][:19].replace('T',' '),r['status']))
        if self.records:
            sid=select_id or self.records[0][0]; self.history.selection_set(str(sid)); self.show(dict(self.records)[sid],sid)
        else:
            self.reset_inspector(False)
            self.current=None; self.current_id=None; self.review_states = {}; self.refresh_checklist(); self.summary.set('No assessment selected'); self.observation_count.set('—'); self.findings.delete(*self.findings.get_children()); self.set_detail('Run an authorized assessment to begin.')
    def history_selected(self,event=None):
        s=self.history.selection()
        if s and int(s[0]) in dict(self.records):self.show(dict(self.records)[int(s[0])],int(s[0]))
    def reset_inspector(self, has_assessment):
        self.highest.set('—')
        self.highest_label.configure(style='Title.TLabel')
        self.remediation_box.configure(state='disabled')
        self.remediation_button.configure(state='disabled')
        self.remediation_state.set('Open')
        self.remediation_updated.set('')
        self.selection_title.set('Select a finding')
        self.selection_meta.set('Choose a row to inspect its evidence.')
        for button in self.result_buttons:
            button.state(['!disabled'] if has_assessment else ['disabled'])

    def show(self,r,sid):
        self.current = r
        self.current_id = sid
        self.review_states = self.store.remediation(self.history_project_id, sid)
        self.checklist_tree.selection_remove(*self.checklist_tree.selection())
        self.refresh_checklist()
        self.findings.delete(*self.findings.get_children())
        self.reset_inspector(True)
        levels = {f['severity'].lower() for f in r['findings']}
        highest = next((level for level in SEVERITY_COLORS if level in levels), None)
        self.highest.set(highest.title() if highest else '—')
        self.highest_label.configure(style=highest + '.Title.TLabel' if highest else 'Title.TLabel')
        coverage = r.get('coverage', {})
        connection = [coverage['tool']] if coverage.get('tool') else [
            f"HTTP {r['http_status']}" if r.get('http_status') else '', r.get('tls')]
        self.summary.set(' · '.join(filter(None, [r['status'].capitalize(), *connection])))
        views = finding_views(r)
        self.presented_findings = {str(v.index): v for v in views}
        self.observation_count.set(str(len(views)))
        for v in views:
            finding = v.finding
            severity = finding['severity']
            title = finding['title'] + (f' ({v.occurrences} identical observations)' if v.occurrences > 1 else '')
            self.findings.insert('', 'end', iid=str(v.index), values=(title, severity.upper()),
                                 tags=(severity.lower(),))
        totals = findings_summary(r)
        self.set_detail(r['target']+f"\n\n{totals['distinct']} distinct findings; {totals['observations']} observations; {totals['exact_repeats']} identical repeats.\n\nCoverage: "+json.dumps(r.get('coverage',{'profile':'legacy v0.1'}),ensure_ascii=False)+'\n\n'+(r['error'] or 'Select a finding for evidence and remediation. These are configuration observations, not verified exploits.'))
    def finding_selected(self,event=None):
        s=self.findings.selection()
        if s and self.current and s[0] in getattr(self, 'presented_findings', {}):
            view = self.presented_findings[s[0]]
            f = view.finding
            self.selection_title.set(f['title'])
            self.selection_meta.set(' · '.join(filter(None, [f['severity'].title(), f.get('source'), 'Confidence: ' + f.get('confidence', 'unknown')])))
            self.set_detail(finding_detail(view))
            self.remediation_box.configure(state='readonly')
            self.remediation_button.configure(state='normal')
            record = self.review_states.get(view.index, {})
            self.remediation_state.set(record.get('state', 'Open'))
            self.remediation_updated.set('Manual status · ' + record['updated'][:10] if record else 'Not reviewed. Status is not proof of a fix.')
        else:
            self.remediation_box.configure(state='disabled')
            self.remediation_button.configure(state='disabled')

    def save_remediation(self):
        selection = (self.checklist_tree.selection() if self.workspace_tabs.select() == str(self.remediation_page)
                     else self.findings.selection())
        if not selection or self.current_id is None or selection[0] not in getattr(self, 'presented_findings', {}):
            return
        view = self.presented_findings[selection[0]]
        try:
            record = self.store.set_remediation(self.history_project_id, self.current_id, view.index,
                                                self.remediation_state.get())
        except ValueError as exc:
            messagebox.showerror('Cannot save status', str(exc), parent=self)
            return
        self.review_states[view.index] = record
        self.refresh_checklist()
        if self.workspace_tabs.select() == str(self.remediation_page):
            self.checklist_selected()
        self.remediation_updated.set('Manual status · ' + record['updated'][:10])
        self.status.set('Remediation status saved for selected observation. Evidence unchanged.')
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
    def retest_evidence(self):
        if not self.current or self.current_id is None:
            return
        previous = next((r for sid, r in self.records
                         if sid < self.current_id
                         and r['target'] == self.current['target']
                         and r.get('profile') == self.current.get('profile')
                         and r.get('dns_domain', '') == self.current.get('dns_domain', '')), None)
        if previous is None:
            self.set_detail('No earlier assessment of the same URL, profile and DNS scope.')
            return
        self.set_detail(review_text(review(previous, self.current)))

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
