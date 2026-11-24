import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from threading import Thread, Event
from queue import Queue, Empty
from pathlib import Path
from .engine import Target, scan, compare
from .store import Store
from .dnscheck import domain_name
import json
from .report import html_report

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Sentinel | Security assessment • v0.2'); self.geometry('1100x740'); self.minsize(850,650)
        self.configure(bg='#101923'); self.store=Store(); self.queue=Queue(); self.current=None; self.records=[]; self.busy=False; self.cancel_event=Event()
        self.protocol('WM_DELETE_WINDOW',self.close)
        style=ttk.Style(self); style.theme_use('clam')
        style.configure('.',font=('Segoe UI',10),background='#172431',foreground='#e4edf3',fieldbackground='#233547',bordercolor='#344759',lightcolor='#344759',darkcolor='#344759')
        style.configure('TButton',padding=8,background='#285364',foreground='#f3f7fa'); style.map('TButton',background=[('active','#39798a'),('disabled','#233547')],foreground=[('disabled','#8b9baa')])
        style.configure('Treeview',background='#172431',fieldbackground='#172431',foreground='#e4edf3',rowheight=30)
        style.configure('Treeview.Heading',background='#233547',foreground='#e4edf3'); style.map('Treeview',background=[('selected','#285364')])
        style.configure('TCheckbutton',background='#172431',foreground='#e4edf3'); style.map('TCheckbutton',background=[('active','#172431')])
        self.project=tk.StringVar(value='My website'); self.url=tk.StringVar(value='https://'); self.auth=tk.BooleanVar(); self.status=tk.StringVar(value='Ready • No assessment run.'); self.summary=tk.StringVar(value='No findings yet')
        header=tk.Frame(self,bg='#101923'); header.pack(fill='x',padx=24,pady=(18,12))
        tk.Label(header,text='SENTINEL',font=('Segoe UI',24,'bold'),bg='#101923',fg='#6de0c0').pack(side='left')
        tk.Label(header,text='  /  SECURITY ASSESSMENT    v0.2 COMMUNITY',bg='#101923',fg='#a7bacb',font=('Segoe UI',10)).pack(side='left')
        ttk.Button(header,text='Security tools…',command=self.open_network).pack(side='right')
        ttk.Button(header,text='Local dependencies',command=self.open_dependencies).pack(side='right',padx=8)
        main=ttk.Frame(self,padding=16); main.pack(fill='both',expand=True,padx=24,pady=(0,12))
        form=ttk.Frame(main); form.pack(fill='x')
        ttk.Label(form,text='Project').grid(row=0,column=0,sticky='w'); ttk.Label(form,text='Authorized URL (one page)').grid(row=0,column=1,sticky='w',padx=12)
        self.project_box=ttk.Combobox(form,textvariable=self.project,values=self.store.projects(),width=24); self.project_box.grid(row=1,column=0,sticky='ew'); self.project_box.bind('<<ComboboxSelected>>',lambda e:self.load_history())
        ttk.Entry(form,textvariable=self.url).grid(row=1,column=1,sticky='ew',padx=12); form.columnconfigure(1,weight=1)
        self.run_btn=ttk.Button(form,text='Run assessment',command=self.run); self.run_btn.grid(row=1,column=2,sticky='ew')
        self.auth_check=ttk.Checkbutton(main,text='I have explicit permission to assess this URL and optional DNS domain.',variable=self.auth); self.auth_check.pack(anchor='w',pady=(12,4))
        self.url.trace_add('write',lambda *_:self.auth.set(False))
        dnsrow=ttk.Frame(main); dnsrow.pack(fill='x',pady=(0,8))
        self.dns=tk.StringVar(); ttk.Label(dnsrow,text='Optional authorized mail domain:').pack(side='left'); ttk.Entry(dnsrow,textvariable=self.dns,width=30).pack(side='left',padx=8)
        self.dns.trace_add('write',lambda *_:self.auth.set(False))
        ttk.Label(dnsrow,text='SPF / DMARC / MX / CAA').pack(side='left')
        ttk.Label(main,text='Scope: one GET; optional 4 DNS lookups; no redirects, login, exploit tests or body storage.').pack(anchor='w',pady=(0,12))
        actions=ttk.Frame(main); actions.pack(fill='x',pady=(0,8))
        ttk.Button(actions,text='Load project history',command=self.load_history).pack(side='left'); ttk.Button(actions,text='Export HTML report',command=self.export).pack(side='left',padx=8); ttk.Button(actions,text='Compare previous scan',command=self.diff).pack(side='left'); ttk.Button(actions,text='Export JSON',command=self.export_json).pack(side='left',padx=8); self.stop_btn=ttk.Button(actions,text='Stop',command=self.stop,state='disabled'); self.stop_btn.pack(side='right')
        ttk.Label(main,textvariable=self.summary,font=('Segoe UI',13,'bold')).pack(anchor='w',pady=6)
        panes=ttk.Panedwindow(main,orient='horizontal'); panes.pack(fill='both',expand=True)
        left=ttk.Frame(panes); right=ttk.Frame(panes); panes.add(left,weight=1); panes.add(right,weight=3)
        ttk.Label(left,text='Assessment history').pack(anchor='w')
        self.history=ttk.Treeview(left,columns=('time','status'),show='headings',height=8); self.history.heading('time',text='UTC time'); self.history.heading('status',text='Status'); self.history.column('time',width=150); self.history.column('status',width=85); self.history.pack(fill='both',expand=True); self.history.bind('<<TreeviewSelect>>',self.history_selected)
        ttk.Label(right,text='Observed findings').pack(anchor='w')
        self.findings=ttk.Treeview(right,columns=('severity','title'),show='headings',height=8); self.findings.heading('severity',text='Severity'); self.findings.heading('title',text='Finding'); self.findings.column('severity',width=80,stretch=False); self.findings.column('title',width=400); self.findings.pack(fill='both',expand=True); self.findings.bind('<<TreeviewSelect>>',self.finding_selected)
        self.detail=tk.Text(right,height=10,wrap='word',bg='#101923',fg='#d9e5ed',relief='flat',font=('Segoe UI',10),padx=10,pady=10); self.detail.pack(fill='both',expand=True,pady=(8,0)); self.set_detail('Select a finding to see evidence and remediation. A clean assessment is not proof of security.')
        tk.Label(self,textvariable=self.status,bg='#101923',fg='#9fc2d4',anchor='w').pack(fill='x',padx=24,pady=(0,14))
        self.after(100,self.poll)
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
        def worker():
            try:self.queue.put((pid,name,scan(target.url,authorized=True,cancel=self.cancel_event,dns_domain=dns).to_dict(),None))
            except Exception as e:self.queue.put((pid,name,None,type(e).__name__))
        Thread(target=worker,daemon=True).start()
    def stop(self):
        if self.busy:
            self.cancel_event.set(); self.stop_btn.configure(state='disabled'); self.status.set('Stopping after current bounded operation…')
    def poll(self):
        try:
            pid,name,result,error=self.queue.get_nowait(); self.busy=False; self.stop_btn.configure(state='disabled'); self.run_btn.configure(state='normal')
            if error:self.status.set('Assessment error: '+error)
            else:
                sid=self.store.save(pid,result); self.project.set(name); self.project_box.configure(values=self.store.projects()); self.load_history(sid); self.status.set('Assessment '+result['status']+' • Saved locally.')
        except Empty:pass
        except Exception as e:self.status.set('Local storage/UI error: '+type(e).__name__)
        self.after(100,self.poll)
    def load_history(self,select_id=None):
        if self.busy:return
        try:pid=self.store.project(self.project.get())
        except ValueError as e:messagebox.showerror('Project',str(e));return
        self.project_box.configure(values=self.store.projects()); self.records=self.store.history(pid); self.history.delete(*self.history.get_children())
        for sid,r in self.records:self.history.insert('','end',iid=str(sid),values=(r['started'][:19].replace('T',' '),r['status']))
        if self.records:
            sid=select_id or self.records[0][0]; self.history.selection_set(str(sid)); self.show(dict(self.records)[sid],sid)
        else:
            self.current=None; self.current_id=None; self.summary.set('No assessments in this project'); self.findings.delete(*self.findings.get_children()); self.set_detail('Run an authorized assessment to begin.')
    def history_selected(self,event=None):
        s=self.history.selection()
        if s and int(s[0]) in dict(self.records):self.show(dict(self.records)[int(s[0])],int(s[0]))
    def show(self,r,sid):
        self.current=r; self.current_id=sid; self.findings.delete(*self.findings.get_children()); self.summary.set(f"{r['status'].upper()}  |  {len(r['findings'])} observations  |  "+(f"{r['coverage'].get('tool','Tool')} {r['coverage'].get('profile','')}" if r.get('coverage',{}).get('tool') else f"HTTP {r['http_status'] or '—'}  |  {r['tls'] or 'No TLS result'}"))
        for i,f in enumerate(r['findings']):self.findings.insert('','end',iid=str(i),values=(f['severity'].upper(),f['title']))
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
        self.cancel_event.set(); self.store.close(); self.destroy()

def main():App().mainloop()
