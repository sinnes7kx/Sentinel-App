"""Beginner window for every integrated security tool."""
from .ui_lifecycle import watch_poll, watch_variables
import tkinter as tk
from .desktop_theme import CANVAS, detail_box
from tkinter import ttk, messagebox
from threading import Event
from .orchestration import for_app
from queue import Queue, Empty
from .tools import TOOLS
from .tools.base import ToolMissing, parse_scope
from .tools.scope import require_authorization
from .tools.backends import Backend, SUPPORTED, is_wsl_distribution
from .tools import wsl

DEFAULTS = {'net': '192.168.1.1', 'web': 'https://'}
LABELS = {'net': 'Target: an IP address, a host name, or a home/office network such as 192.168.1.0/24',
          'web': 'Target: the full web address, for example https://example.com'}


class ToolsWindow(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app)
        watch_poll(self)
        self.orchestrator = for_app(app)
        self.app = app; self.queue = Queue(); self.busy = False; self.cancel_event = Event(); self.result = None
        self.title('Sentinel | Security tools'); self.geometry('940x720'); self.minsize(780, 600); self.configure(bg=CANVAS)
        self.tool = TOOLS[0]; self.target = tk.StringVar(value=DEFAULTS['web']); self.profile = tk.StringVar()
        self.auth = tk.BooleanVar(); self.confirm = tk.StringVar(); self.status = tk.StringVar(value='Ready.')
        self.tool_name = tk.StringVar(value=self.tool.name); self.info = tk.StringVar(); self.label = tk.StringVar()
        self.backend = tk.StringVar(value='native'); self.environment = tk.StringVar()
        self.environment_values = {'wsl': '', 'docker': ''}
        self.active_backend = 'native'
        self.wsl_names = []
        self.wsl_status = tk.StringVar()
        self.wsl_queue = Queue()
        self.wsl_busy = False
        self.wsl_cancel = Event()
        self.bind('<Destroy>', self.cancel_wsl_probe, add='+')
        body = ttk.Frame(self, padding=16); body.pack(fill='both', expand=True, padx=16, pady=16)
        ttk.Label(body, text='Choose a check', font=('Segoe UI', 14, 'bold')).pack(anchor='w')
        box = ttk.Combobox(body, textvariable=self.tool_name, values=[t.name for t in TOOLS], state='readonly'); box.pack(fill='x', pady=(4, 2))
        box.bind('<<ComboboxSelected>>', self.tool_changed)
        ttk.Label(body, textvariable=self.info, wraplength=860, justify='left').pack(anchor='w', pady=(2, 8))
        ttk.Label(body, textvariable=self.label).pack(anchor='w')
        row = ttk.Frame(body); row.pack(fill='x'); row.columnconfigure(0, weight=1)
        ttk.Entry(row, textvariable=self.target).grid(row=0, column=0, sticky='ew')
        self.run_btn = ttk.Button(row, text='Start', command=self.start); self.run_btn.grid(row=0, column=1, padx=(10, 0))
        self.stop_btn = ttk.Button(row, text='Stop', command=self.stop, state='disabled'); self.stop_btn.grid(row=0, column=2, padx=(8, 0))
        self.profiles = ttk.Frame(body); self.profiles.pack(fill='x', pady=8)
        back = ttk.Frame(body); back.pack(fill='x', pady=4)
        ttk.Label(back, text='Run using').pack(side='left')
        ttk.Combobox(back, textvariable=self.backend, values=['native', 'wsl', 'docker'], state='readonly', width=10).pack(side='left', padx=8)
        self.environment_label = ttk.Label(back)
        self.environment_box = ttk.Combobox(back, textvariable=self.environment)
        self.wsl_controls = ttk.Frame(body)
        self.detect_wsl_button = ttk.Button(self.wsl_controls, text='Detect distributions', command=self.detect_wsl)
        self.detect_wsl_button.pack(side='left')
        self.check_wsl_button = ttk.Button(self.wsl_controls, text='Check installed tools', command=self.check_wsl)
        self.check_wsl_button.pack(side='left', padx=6)
        ttk.Label(self.wsl_controls, textvariable=self.wsl_status, style='Muted.TLabel',
                  wraplength=480).pack(side='left', fill='x')
        ttk.Checkbutton(body, text='I own this target or have written permission to test it.', variable=self.auth).pack(anchor='w', pady=(4, 2))
        conf = self.confirm_row = ttk.Frame(body); conf.pack(fill='x', pady=(0, 8))
        ttk.Label(conf, text='Only for targets outside your private network — type the host name or IP again to confirm:').pack(side='left')
        ttk.Entry(conf, textvariable=self.confirm, width=26).pack(side='left', padx=8)
        self.bar = ttk.Progressbar(body, mode='indeterminate'); self.bar.pack(fill='x', pady=(0, 8))
        self.tree = ttk.Treeview(body, columns=('sev', 'title'), show='headings', height=8)
        self.tree.heading('sev', text='Risk'); self.tree.heading('title', text='What was found')
        self.tree.column('sev', width=80, stretch=False); self.tree.column('title', width=640)
        self.tree.pack(fill='both', expand=True); self.tree.bind('<<TreeviewSelect>>', self.selected)
        self.detail = detail_box(body, height=9)
        self.detail.pack(fill='both', expand=True, pady=(8, 0))
        ttk.Label(self, textvariable=self.status, style='Canvas.TLabel').pack(fill='x', padx=16, pady=(0, 10))
        watch_variables(self, (self.target, self.profile, self.backend, self.environment),
                        lambda *_: self.auth.set(False))
        watch_variables(self, (self.backend,), self.backend_changed)
        watch_variables(self, (self.environment,), self.environment_changed)
        self.update_backend_controls()
        self.refresh_tool(); self.protocol('WM_DELETE_WINDOW', self.close); self.poll_timer = self.after(150, self.poll)

    def update_backend_controls(self):
        kind = self.backend.get()
        self.environment_label.configure(text={'native': '', 'wsl': 'Distribution', 'docker': 'Image digest'}[kind])
        self.environment_box.configure(values=self.wsl_names if kind == 'wsl' else (),
                                       state='disabled' if self.wsl_busy else 'normal')
        if kind == 'native':
            self.environment_label.pack_forget()
            self.environment_box.pack_forget()
        elif not self.environment_box.winfo_manager():
            self.environment_label.pack(side='left', padx=(0, 6))
            self.environment_box.pack(side='left', fill='x', expand=True)
        if kind == 'wsl':
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
        self.update_backend_controls()

    def detect_wsl(self):
        self.start_wsl_probe('list', '', lambda _cancel: wsl.distributions())

    def check_wsl(self):
        name = self.environment.get().strip()
        self.start_wsl_probe('tools', name, lambda cancel: wsl.available_tools(name, cancel))

    def start_wsl_probe(self, action, name, operation):
        if self.busy or self.wsl_busy or self.backend.get() != 'wsl':
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
        self.wsl_status.set('Checking WSL…')

    def poll_wsl_probe(self):
        try:
            action, name, result, error = self.wsl_queue.get_nowait()
        except Empty:
            return
        self.wsl_busy = False
        self.run_btn.state(['!disabled'])
        self.update_backend_controls()
        if self.backend.get() != 'wsl':
            return
        error = error or result.get('error')
        if error:
            self.wsl_status.set(error)
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
        old = self.tool.kind; self.tool = next(t for t in TOOLS if t.name == self.tool_name.get())
        if self.tool.kind != old and self.target.get() in DEFAULTS.values(): self.target.set(DEFAULTS[self.tool.kind])
        self.auth.set(False); self.refresh_tool()

    def update_tool_info(self):
        t = self.tool
        kind = self.backend.get()
        if kind == 'native':
            availability = '' if t.installed() else '\nTool is missing locally. Press Start for installation details.'
        elif t.id not in SUPPORTED:
            availability = '\nSelect Nmap, sslscan, or WhatWeb to use this backend.'
        else:
            availability = '\nUses the executable installed in the selected environment.'
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
            messagebox.showinfo('Tool needed', str(e), parent=self); return
        except (ValueError, PermissionError) as e:
            messagebox.showerror('Cannot start', str(e), parent=self); return
        self.busy = True; self.cancel_event = Event(); self.run_btn.configure(state='disabled'); self.stop_btn.configure(state='normal')
        self.update_backend_controls()
        self.tree.delete(*self.tree.get_children()); self.bar.start(12); self.status.set(f'Running {self.tool.name}…'); self.say('Running. Some checks take several minutes; you can press Stop at any time.')
        tool, value, prof, conf, ev = self.tool, self.target.get(), self.profile.get(), self.confirm.get(), self.cancel_event
        queue = self.queue
        self.auth.set(False)
        try:
            self.job = self.orchestrator.submit(
                lambda: tool.scan(value, prof, True, conf, ev, **({'backend': backend} if tool.id != 'web-checkup' else {})).to_dict(),
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
            else:
                self.result = res; sid = self.app.store.save(pid, res)
                for i, f in enumerate(res['findings']): self.tree.insert('', 'end', iid=str(i), values=(f['severity'].upper(), f['title']))
                n = len(res['findings']); self.status.set(f"{res['status'].capitalize()} • {n} finding{'s' if n != 1 else ''} • Saved to project history.")
                cov = ', '.join(f'{k}: {v}' for k, v in res['coverage'].items() if k in ('built-in checks', 'whatweb', 'sslscan', 'nikto'))
                self.say((res['error'] or ('Click a row for details.' if n else 'Nothing was found with these settings. That does not prove the system is secure.')) + ('\n\nCoverage — ' + cov if cov else ''))
                self.app.project.set(name); self.app.load_history(sid)
        except Empty: pass
        except Exception as e: self.status.set('Error: ' + type(e).__name__)
        if self.winfo_exists(): self.poll_timer = self.after(150, self.poll)

    def selected(self, _=None):
        s = self.tree.selection()
        if s and self.result:
            f = self.result['findings'][int(s[0])]; self.say(f"{f['title']}\nConfidence: {f.get('confidence', 'unknown')} | Source: {f.get('source', 'legacy')}\n\nWHAT WE SAW\n{f['evidence']}\n\nWHAT TO DO\n{f['remediation']}")

    def close(self):
        if self.busy and not messagebox.askyesno('Exit', 'A check is running. Stop it and close?', parent=self): return
        self.cancel_event.set(); self.destroy()
