"""Beginner window for every integrated security tool."""
from .ui_lifecycle import watch_poll, watch_variables, watch_authorized_scope, bind_escape
from .finding_views import finding_views, finding_detail
import tkinter as tk
from .desktop_theme import CANVAS, PANEL, SEVERITY_COLORS, detail_box, scrollable
from tkinter import ttk, messagebox
from threading import Event
from .orchestration import for_app
from queue import Queue, Empty
from .tools import TOOLS
from .tools.base import ToolMissing, parse_scope
from .tools.scope import require_authorization
from .tools.backends import Backend, SUPPORTED, is_wsl_distribution
from .tools import bundle, wsl
from .tool_setup import saved_source_backend
import os

DEFAULTS = {'net': '192.168.1.1', 'web': 'https://'}
LABELS = {'net': 'Target: an IP address, a host name, or a home/office network such as 192.168.1.0/24',
          'web': 'Target: the full web address, for example https://example.com'}


class ToolsWindow(tk.Toplevel):
    def __init__(self, app, **options):
        super().__init__(app, **options)
        bind_escape(self, self.close)
        watch_poll(self)
        self.orchestrator = for_app(app)
        self.app = app; self.queue = Queue(); self.busy = False; self.cancel_event = Event(); self.result = None
        self.title('Sentinel | Security tools'); self.geometry('1000x750'); self.minsize(820, 650); self.configure(bg=CANVAS)
        self.tool = TOOLS[0]; self.target = tk.StringVar(value=DEFAULTS['web']); self.profile = tk.StringVar()
        self.auth = tk.BooleanVar(); self.confirm = tk.StringVar(); self.status = tk.StringVar(value='Ready.')
        self.tool_name = tk.StringVar(value=self.tool.name); self.info = tk.StringVar(); self.label = tk.StringVar()
        self.backend = tk.StringVar(value='native'); self.environment = tk.StringVar()
        self.environment_values = {'wsl': '', 'docker': ''}
        self.active_backend = 'native'
        self.bundled = os.name == 'nt' and (bundle.PAYLOAD / 'rootfs.sha256').is_file()
        if self.bundled:
            preferred = bundle.saved_backend()
            self.backend.set(preferred.kind)
            self.active_backend = preferred.kind
            self.environment.set(preferred.environment)
            self.environment_values[preferred.kind] = preferred.environment
            self.tool = next(tool for tool in TOOLS if tool.id == 'whatweb')
            self.tool_name.set(self.tool.name)
        self.wsl_names = []
        self.wsl_status = tk.StringVar()
        self.wsl_queue = Queue()
        self.wsl_busy = False
        self.wsl_cancel = Event()
        self.bind('<Destroy>', self.cancel_wsl_probe, add='+')
        shell = ttk.Frame(self, padding=16, style='Canvas.TFrame')
        shell.pack(fill='both', expand=True)
        ttk.Label(shell, text='Security tools', style='WorkspaceTitle.TLabel').pack(anchor='w')
        ttk.Label(shell, text='Choose a check, prepare its engine, then review evidence and fixes.',
                  style='Canvas.TLabel').pack(anchor='w', pady=(2, 10))
        self.tabs = ttk.Notebook(shell)
        self.tabs.pack(fill='both', expand=True)
        self.setup_page = ttk.Frame(self.tabs)
        results = self.results_page = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(self.setup_page, text='1. Configure assessment')
        self.tabs.add(results, text='2. Findings & evidence')
        # Keep authorization and setup controls reachable on smaller displays.
        canvas = tk.Canvas(self.setup_page, background=PANEL, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.setup_page, orient='vertical', command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
        canvas.pack(side='left', fill='both', expand=True)
        body = ttk.Frame(canvas, padding=12)
        body_id = canvas.create_window((0, 0), window=body, anchor='nw')
        body.bind('<Configure>', lambda event: canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.bind('<Configure>', lambda event: canvas.itemconfigure(body_id, width=event.width))
        ttk.Label(body, text='Choose a security check', style='Title.TLabel').pack(anchor='w')
        box = ttk.Combobox(body, textvariable=self.tool_name, values=[t.name for t in TOOLS], state='readonly')
        box.pack(fill='x', pady=(4, 2))
        box.bind('<<ComboboxSelected>>', self.tool_changed)
        ttk.Label(body, textvariable=self.info, wraplength=745, justify='left').pack(anchor='w', pady=(2, 8))
        ttk.Label(body, textvariable=self.label, wraplength=745).pack(anchor='w')
        ttk.Entry(body, textvariable=self.target).pack(fill='x', pady=(3, 6))
        self.profiles = ttk.Frame(body)
        self.profiles.pack(fill='x', pady=(2, 8))
        ttk.Separator(body).pack(fill='x', pady=(0, 8))
        ttk.Label(body, text='Execution engine', style='Title.TLabel').pack(anchor='w')
        self.engine_hint = tk.StringVar()
        ttk.Label(body, textvariable=self.engine_hint, wraplength=745,
                  style='Muted.TLabel').pack(anchor='w', pady=(2, 5))
        back = ttk.Frame(body)
        back.pack(fill='x', pady=4)
        ttk.Label(back, text='Run using').pack(side='left')
        ttk.Combobox(back, textvariable=self.backend, values=['native', 'wsl', 'docker'],
                     state='readonly', width=10).pack(side='left', padx=8)
        self.environment_label = ttk.Label(back)
        self.environment_box = ttk.Combobox(back, textvariable=self.environment)
        self.wsl_controls = ttk.Frame(body)
        self.prepare_button = ttk.Button(self.wsl_controls, text='Prepare included tools', command=self.prepare_bundle)
        self.detect_wsl_button = ttk.Button(self.wsl_controls, text='Detect distributions', command=self.detect_wsl)
        self.detect_wsl_button.pack(side='left')
        self.check_wsl_button = ttk.Button(self.wsl_controls, text='Check installed tools', command=self.check_wsl)
        self.check_wsl_button.pack(side='left', padx=6)
        if os.name == 'nt':
            ttk.Button(body, text='Install / prepare security tools', command=self.open_tool_setup,
                       style='Primary.TButton').pack(anchor='w', pady=(4, 6))
        self.saved_toolkit_button = ttk.Button(body, text='Use saved Kali toolkit', command=self.use_saved_toolkit)
        if self.bundled or os.name == 'nt':
            self.saved_toolkit_button.pack(anchor='w', pady=(2, 4))
        self.preparation_status = ttk.Label(body, textvariable=self.wsl_status, style='Muted.TLabel',
                                            wraplength=745)
        self.preparation_status.pack(anchor='w')
        conf = self.confirm_row = ttk.Frame(body)
        conf.pack(fill='x', pady=(6, 0))
        ttk.Checkbutton(conf, text='I have permission for this exact target and check (remembered until scope changes).',
                        variable=self.auth).pack(anchor='w', pady=(0, 4))
        ttk.Label(conf, text='Public targets: type the hostname or IP again to confirm.',
                  wraplength=745).pack(anchor='w')
        ttk.Entry(conf, textvariable=self.confirm, width=32).pack(anchor='w', pady=3)

        action = ttk.Frame(shell, style='Canvas.TFrame')
        action.pack(fill='x', pady=(8, 0))
        self.run_btn = ttk.Button(action, text='Start assessment', command=self.start, style='Primary.TButton')
        self.run_btn.pack(side='right')
        self.stop_btn = ttk.Button(action, text='Stop', command=self.stop, state='disabled')
        self.stop_btn.pack(side='right', padx=6)
        ttk.Label(action, textvariable=self.status, style='Canvas.TLabel', wraplength=500).pack(side='left', fill='x', expand=True)
        self.bar = ttk.Progressbar(shell, mode='indeterminate', style='Scan.Horizontal.TProgressbar')
        self.bar.pack(fill='x', pady=(6, 0))
        panes = ttk.Panedwindow(results, orient='horizontal')
        panes.pack(fill='both', expand=True)
        listing = ttk.Frame(panes, padding=6)
        evidence = ttk.Frame(panes, padding=6)
        panes.add(listing, weight=4)
        panes.add(evidence, weight=5)
        ttk.Label(listing, text='Findings', style='Title.TLabel').pack(anchor='w', pady=(0, 6))
        table = ttk.Frame(listing)
        table.pack(fill='both', expand=True)
        self.tree = ttk.Treeview(table, columns=('sev', 'title'), show='headings', height=8)
        self.tree.heading('sev', text='Risk')
        self.tree.heading('title', text='What was found')
        self.tree.column('sev', width=80, stretch=False)
        self.tree.column('title', width=240, minwidth=100)
        for level, color in SEVERITY_COLORS.items():
            self.tree.tag_configure(level, foreground=color)
        scrollable(table, self.tree)
        self.tree.bind('<<TreeviewSelect>>', self.selected)
        ttk.Label(evidence, text='Evidence & remediation', style='Title.TLabel').pack(anchor='w', pady=(0, 6))
        detail = ttk.Frame(evidence)
        detail.pack(fill='both', expand=True)
        self.detail = detail_box(detail, height=9)
        scrollable(detail, self.detail)
        watch_authorized_scope(self, (self.app.project, self.tool_name, self.target, self.profile,
                                      self.backend, self.environment), self.auth)
        watch_variables(self, (self.backend,), self.backend_changed)
        watch_variables(self, (self.environment,), self.environment_changed)
        self.update_backend_controls()
        self.refresh_tool(); self.protocol('WM_DELETE_WINDOW', self.close); self.poll_timer = self.after(150, self.poll)

    def update_backend_controls(self):
        kind = self.backend.get()
        self.engine_hint.set({
            'native': 'Windows/local executable. No Kali setup needed if the tool is installed.',
            'wsl': 'Kali or another installed WSL distribution. Guest cancellation is limited.',
            'docker': 'Local Docker daemon and immutable image. Network egress is not isolated to the target.',
        }[kind])
        self.saved_toolkit_button.state(['disabled'] if self.busy or self.wsl_busy or
                                         self.tool.id not in bundle.BUNDLED_TOOLS else ['!disabled'])
        self.environment_label.configure(text={'native': '', 'wsl': 'Distribution', 'docker': 'Image ID or digest'}[kind])
        self.environment_box.configure(values=self.wsl_names if kind == 'wsl' else (),
                                       state='disabled' if self.wsl_busy else 'normal')
        if kind == 'native':
            self.environment_label.pack_forget()
            self.environment_box.pack_forget()
        elif not self.environment_box.winfo_manager():
            self.environment_label.pack(side='left', padx=(0, 6))
            self.environment_box.pack(side='left', fill='x', expand=True)
        if self.bundled and kind in ('wsl', 'docker'):
            self.prepare_button.pack(side='right')
            self.prepare_button.state(['disabled'] if self.wsl_busy or self.busy else ['!disabled'])
        else:
            self.prepare_button.pack_forget()
        if kind == 'wsl' or (self.bundled and kind == 'docker'):
            if not self.wsl_controls.winfo_manager():
                self.wsl_controls.pack(before=self.confirm_row, fill='x', pady=(0, 4))
        else:
            self.wsl_controls.pack_forget()
        self.detect_wsl_button.state(['disabled'] if kind != 'wsl' or self.wsl_busy or self.busy else ['!disabled'])
        self.check_wsl_button.state(['disabled'] if kind != 'wsl' or self.wsl_busy or self.busy
                                    or not is_wsl_distribution(self.environment.get().strip()) else ['!disabled'])

    def backend_changed(self, *_):
        if self.active_backend != 'native':
            self.environment_values[self.active_backend] = self.environment.get()
        self.active_backend = self.backend.get()
        self.environment.set(self.environment_values.get(self.active_backend, ''))
        self.update_backend_controls()
        self.update_tool_info()

    def environment_changed(self, *_):
        self.wsl_status.set('')
        self.update_tool_info()
        self.update_backend_controls()

    def open_tool_setup(self):
        from .tool_setup_window import ToolSetupWindow
        window = self.children.get('tool_setup')
        if window is None:
            window = ToolSetupWindow(self)
        else:
            window.deiconify()
            window.lift()
        return window

    def use_saved_toolkit(self):
        if self.busy or self.wsl_busy or self.tool.id not in bundle.BUNDLED_TOOLS:
            return
        saved = bundle.saved_backend() if self.bundled else saved_source_backend()
        if saved is None:
            self.wsl_status.set('No saved toolkit yet. Choose Install / prepare security tools.')
            return
        try:
            saved.validate(self.tool.id)
        except ValueError:
            self.wsl_status.set('No saved toolkit yet. Choose WSL or Docker, then Prepare included tools.')
            return
        self.backend.set(saved.kind)
        self.environment.set(saved.environment)
        self.wsl_status.set('Saved toolkit selected. Current runtime and scan connectivity are not verified.')

    def prepare_bundle(self):
        kind = self.backend.get()
        if not self.bundled or kind not in ('wsl', 'docker'):
            return
        def provision(_cancel):
            try:
                backend = bundle.prepare(kind)
                bundle.remember(backend, bundle.preference_path())
            except OSError as exc:
                raise ValueError(f'Toolkit setup could not access a local file ({exc.strerror}).') from exc
            return backend.environment
        self.start_wsl_probe('prepare', kind, provision)

    def detect_wsl(self):
        self.start_wsl_probe('list', '', lambda _cancel: wsl.distributions())

    def check_wsl(self):
        name = self.environment.get().strip()
        self.start_wsl_probe('tools', name, lambda cancel: wsl.available_tools(name, cancel))

    def start_wsl_probe(self, action, name, operation):
        if self.busy or self.wsl_busy or (action != 'prepare' and self.backend.get() != 'wsl'):
            return
        queue = self.wsl_queue
        cancel = self.wsl_cancel = Event()

        def inspect():
            try:
                return {'values': operation(cancel)}
            except ValueError as exc:
                return {'status': 'failed', 'error': str(exc)}

        try:
            self.orchestrator.submit(inspect, lambda result, error: queue.put((action, name, result, error)), cancel)
        except RuntimeError as exc:
            self.wsl_status.set(str(exc))
            return
        self.wsl_busy = True
        self.run_btn.state(['disabled'])
        self.update_backend_controls()
        self.wsl_status.set('Preparing the included Kali tools…' if action == 'prepare' else 'Checking WSL…')

    def poll_wsl_probe(self):
        try:
            action, name, result, error = self.wsl_queue.get_nowait()
        except Empty:
            return
        self.wsl_busy = False
        self.run_btn.state(['!disabled'])
        self.update_backend_controls()
        if self.backend.get() != (name if action == 'prepare' else 'wsl'):
            return
        error = error or result.get('error')
        if error:
            self.wsl_status.set(error)
        elif action == 'prepare':
            self.environment.set(result['values'])
            self.wsl_status.set('Prepared · WhatWeb and sslscan detected; scan connectivity not verified.')
        elif action == 'list':
            self.wsl_names = result['values']
            if self.wsl_names and self.environment.get().strip() not in self.wsl_names:
                self.environment.set(self.wsl_names[0])
            self.update_backend_controls()
            self.wsl_status.set(f'{len(self.wsl_names)} distribution(s) detected.' if self.wsl_names
                                else 'No distributions found. To add Kali, see the WSL setup in the README.')
        elif name == self.environment.get().strip():
            found = set(result['values'])
            installed = sorted(SUPPORTED & found)
            missing = sorted(SUPPORTED - found)
            parts = []
            if installed:
                parts.append('Available — ' + ', '.join(installed))
            if missing:
                parts.append('Missing — ' + ', '.join(missing))
            if 'timeout' not in found:
                parts.append('GNU timeout is required')
            self.wsl_status.set(' · '.join(parts))

    def cancel_wsl_probe(self, event):
        if event.widget is self:
            self.wsl_cancel.set()

    def say(self, text):
        self.detail.configure(state='normal'); self.detail.delete('1.0', 'end'); self.detail.insert('1.0', text); self.detail.configure(state='disabled')

    def tool_changed(self, _=None):
        chosen = next(t for t in TOOLS if t.name == self.tool_name.get())
        if chosen.id == self.tool.id:
            return
        old = self.tool.kind; self.tool = chosen
        if self.tool.kind != old and self.target.get() in DEFAULTS.values(): self.target.set(DEFAULTS[self.tool.kind])
        self.auth.set(False); self.refresh_tool(); self.update_backend_controls()

    def update_tool_info(self):
        t = self.tool
        kind = self.backend.get()
        if kind == 'native':
            availability = '' if t.installed() else '\nTool is not installed in Windows. Press Start for installation instructions, or choose a prepared Linux engine.'
        elif self.bundled and not self.environment.get().strip():
            availability = '\nChoose Prepare included tools for WhatWeb and sslscan. WSL setup may request administrator access and a restart.'
        elif t.id not in SUPPORTED:
            availability = '\nSelect Nmap, sslscan, or WhatWeb to use this backend.'
        else:
            availability = '\nUses the executable installed in the selected environment. WSL availability is checked before each assessment.'
        self.info.set(t.blurb + availability + (('\n' + t.note) if t.note else ''))

    def refresh_tool(self):
        t = self.tool
        self.update_tool_info()
        self.label.set(LABELS[t.kind])
        for w in self.profiles.winfo_children(): w.destroy()
        first = next(iter(t.profiles)); self.profile.set(first)
        for p in t.profiles.values():
            ttk.Radiobutton(self.profiles, text=f'{p.label} — {p.blurb}', variable=self.profile, value=p.id).pack(anchor='w')
        self.say('Results appear here. Click a row for a plain-English explanation and how to fix it.')

    def start(self):
        if self.busy or self.wsl_busy: return
        try:
            if not self.auth.get(): raise PermissionError('Confirm that you own this target or have written permission to test it.')
            backend = Backend(self.backend.get(), self.environment.get().strip())
            backend.validate(self.tool.id)
            if backend.kind == 'native' and not self.tool.installed(): raise ToolMissing(self.tool.install_hint)
            if backend.kind == 'wsl':
                if not messagebox.askokcancel('WSL execution', 'WSL execution is experimental. Stop ends the Windows launcher, but Linux work may continue until its profile time limit. Use native or Docker for stronger cancellation. Continue?', parent=self): return
            name = self.app.project.get(); pid = self.app.store.project(name)
        except ToolMissing as e:
            if os.name == 'nt' and self.tool.id == 'nmap':
                self.open_tool_setup()
            else:
                messagebox.showinfo('Tool needed', str(e), parent=self)
            return
        except (ValueError, PermissionError) as e:
            messagebox.showerror('Cannot start', str(e), parent=self); return
        self.busy = True; self.cancel_event = Event(); self.run_btn.configure(state='disabled'); self.stop_btn.configure(state='normal')
        self.update_backend_controls()
        self.tabs.select(self.results_page)
        self.result = None
        self.presented_findings = {}
        self.tree.delete(*self.tree.get_children()); self.bar.start(12); self.status.set(f'Running {self.tool.name}…'); self.say('Running. Some checks take several minutes; you can press Stop at any time.')
        tool, value, prof, conf, ev = self.tool, self.target.get(), self.profile.get(), self.confirm.get(), self.cancel_event
        queue = self.queue
        def operation():
            if backend.kind == 'wsl':
                try:
                    installed = wsl.available_tools(backend.environment, ev)
                except ValueError as exc:
                    return {'status': 'failed', 'setup_error': str(exc)}
                if ev.is_set():
                    return {'status': 'cancelled', 'setup_error': 'Cancelled during engine check.'}
                missing = [name for name in ('timeout', tool.id) if name not in installed]
                if missing:
                    return {'status': 'failed', 'setup_error':
                            'Missing in selected WSL distribution: ' + ', '.join(missing) +
                            '. Open that Linux terminal and install the required packages. ' +
                            ('For Nmap: sudo apt update && sudo apt install nmap.' if tool.id == 'nmap'
                             else 'For Kali/Debian, use the package manager or Prepare included tools.')}
            return tool.scan(value, prof, True, conf, ev, **({'backend': backend} if tool.id != 'web-checkup' else {})).to_dict()
        try:
            self.job = self.orchestrator.submit(
                operation,
                lambda result, error: queue.put((pid, name, result, error)), ev)
            self.status.set('Queued; one check runs at a time.')
        except RuntimeError as exc:
            self.queue.put((pid, name, None, str(exc)))

    def stop(self):
        if self.busy: self.cancel_event.set(); self.stop_btn.configure(state='disabled'); self.status.set('Stopping…')

    def poll(self):
        self.poll_wsl_probe()
        if self.busy and hasattr(self, 'job') and not self.cancel_event.is_set():
            self.status.set(self.job.state.capitalize() + ' • security check')
        try:
            pid, name, res, err = self.queue.get_nowait()
            self.busy = False; self.bar.stop(); self.run_btn.configure(state='normal'); self.stop_btn.configure(state='disabled')
            self.update_backend_controls()
            if err: self.status.set('Error: ' + err); self.say('The check could not run. ' + err)
            elif res.get('setup_error'):
                self.status.set(res['setup_error'])
                self.say(res['setup_error'])
                self.tabs.select(self.setup_page)
                self.wsl_status.set(res['setup_error'])
            else:
                self.result = res; sid = self.app.store.save(pid, res)
                views = finding_views(res)
                self.presented_findings = {str(v.index): v for v in views}
                for v in views:
                    f = v.finding
                    title = f['title'] + (f' ({v.occurrences} identical observations)' if v.occurrences > 1 else '')
                    self.tree.insert('', 'end', iid=str(v.index), values=(f['severity'].upper(), title), tags=(f['severity'].lower(),))
                n = len(views); self.status.set(f"{res['status'].capitalize()} • {n} finding{'s' if n != 1 else ''} • Saved to project history.")
                cov = ', '.join(f'{k}: {v}' for k, v in res['coverage'].items() if k in ('built-in checks', 'whatweb', 'sslscan', 'nikto'))
                self.say((res['error'] or ('Click a row for details.' if n else 'Nothing was found with these settings. That does not prove the system is secure.')) + ('\n\nCoverage — ' + cov if cov else ''))
                self.app.project.set(name); self.app.load_history(sid)
        except Empty: pass
        except Exception as e: self.status.set('Error: ' + type(e).__name__)
        if self.winfo_exists(): self.poll_timer = self.after(150, self.poll)

    def selected(self, _=None):
        s = self.tree.selection()
        if s and self.result and s[0] in getattr(self, 'presented_findings', {}):
            self.say(finding_detail(self.presented_findings[s[0]]))

    def close(self):
        if self.busy or self.wsl_busy:
            if not messagebox.askyesno('Exit', 'An operation is running. Request cancellation and close the window?', parent=self):
                return
            self.cancel_event.set()
            self.wsl_cancel.set()
            # Keep the worker callbacks alive until they finish. A hidden
            # window retains its exact scope and can be reopened to inspect it.
        self.withdraw()
