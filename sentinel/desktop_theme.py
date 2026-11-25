"""Shared colors and controls for the native desktop workspace."""
import tkinter as tk
from tkinter import ttk

CANVAS = '#111416'
PANEL = '#1b1f22'
SURFACE = '#15191c'
RAISED = '#293137'
LINE = '#394249'
INK = '#eef3f5'
MUTED = '#a9b8c2'
ACCENT = '#a6ded0'
SEVERITY_COLORS = {'critical': '#ff989e', 'high': '#ffa8a5',
                   'medium': '#ffd095', 'low': '#b5cbe3', 'info': MUTED}


def configure_theme(root):
    root.configure(background=CANVAS)
    root.option_add('*TCombobox*Listbox.background', SURFACE)
    root.option_add('*TCombobox*Listbox.foreground', INK)
    root.option_add('*TCombobox*Listbox.selectBackground', RAISED)
    root.option_add('*TCombobox*Listbox.selectForeground', INK)
    style = ttk.Style(root)
    style.theme_use('clam')
    style.configure('.', font=('Segoe UI', 10), background=PANEL, foreground=INK,
                    fieldbackground=SURFACE, bordercolor=LINE, lightcolor=LINE,
                    darkcolor=LINE, arrowcolor=MUTED, insertcolor=INK, focuscolor=ACCENT)
    style.configure('Canvas.TFrame', background=CANVAS)
    style.configure('Canvas.TLabel', background=CANVAS, foreground=MUTED)
    style.configure('Brand.TLabel', background=CANVAS, foreground=ACCENT, font=('Segoe UI', 19, 'bold'))
    style.configure('Title.TLabel', font=('Segoe UI', 13, 'bold'))
    style.configure('Muted.TLabel', foreground=MUTED)
    style.configure('TEntry', padding=6)
    style.configure('TCombobox', padding=6)
    style.map('TCombobox', fieldbackground=[('readonly', SURFACE)])
    style.configure('TButton', padding=(10, 6), background=RAISED)
    style.map('TButton', background=[('disabled', SURFACE), ('active', '#36434a')],
              foreground=[('disabled', MUTED)])
    style.configure('Primary.TButton', background=ACCENT, foreground='#142624')
    style.map('Primary.TButton', background=[('disabled', RAISED), ('active', '#c1eee2')],
              foreground=[('disabled', MUTED)])
    style.configure('Treeview', background=SURFACE, fieldbackground=SURFACE, rowheight=27)
    style.configure('Treeview.Heading', background=RAISED, foreground=INK, padding=(6, 5))
    style.map('Treeview', background=[('selected', '#35504e')], foreground=[('selected', INK)])
    style.map('Treeview.Heading', background=[('active', RAISED)])
    style.configure('Vertical.TScrollbar', troughcolor=SURFACE, background=RAISED, arrowsize=12,
                    bordercolor=LINE, lightcolor=LINE, darkcolor=LINE)
    style.configure('TNotebook.Tab', padding=(12, 7), bordercolor=LINE, lightcolor=LINE, darkcolor=LINE)
    style.map('TNotebook.Tab', background=[('selected', PANEL), ('!selected', CANVAS)])


def detail_box(parent, height=8):
    return tk.Text(parent, height=height, wrap='word', background=SURFACE, foreground=INK,
                   selectbackground='#35504e', selectforeground=INK, relief='flat',
                   highlightthickness=1, highlightbackground=LINE, highlightcolor=ACCENT,
                   font=('Segoe UI', 10), padx=10, pady=9)


def scrollable(parent, widget):
    scrollbar = ttk.Scrollbar(parent, orient='vertical', command=widget.yview)
    widget.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side='right', fill='y')
    widget.pack(side='left', fill='both', expand=True)
