"""Graphite desktop theme with shared image-backed rounded controls."""
import tkinter as tk
from tkinter import ttk

CANVAS = '#101012'
PANEL = '#1b1b1e'
SURFACE = '#151518'
RAISED = '#29292e'
LINE = '#343438'
INK = '#e9e9ed'
MUTED = '#aaaab3'
ACCENT = '#d8d8df'
HEADER = '#121214'
SELECT = '#36363d'
SEVERITY_COLORS = {'critical': '#ff6482', 'high': '#ff9060',
                   'medium': '#f5cf55', 'low': '#65d6a0', 'info': '#78bdf9'}


def _tile(root, fill, radius=9, outline=None):
    """Transparent rounded corners; center stretches as a nine-slice."""
    size = 2 * radius + 3
    tile = tk.PhotoImage(master=root, width=size, height=size)
    for y in range(size):
        for x in range(size):
            dx = max(radius - x - .5, x + .5 - (size - radius), 0)
            dy = max(radius - y - .5, y + .5 - (size - radius), 0)
            distance = (dx * dx + dy * dy) ** .5
            if distance <= radius:
                edge = (distance > radius - 1 or x == 0 or y == 0
                        or x == size - 1 or y == size - 1)
                tile.put(outline if outline and edge else fill, to=(x, y))
    return tile


def _rounded_button(root, style, name, colors, padding, foreground=INK, anchor='center'):
    radius = 8
    normal, hover, pressed, disabled, focused = [
        _tile(root, color, radius, ACCENT if i == 4 else None)
        for i, color in enumerate(colors)]
    root._graphite_images.extend((normal, hover, pressed, disabled, focused))
    element = name + '.surface'
    style.element_create(element, 'image', normal,
                         ('disabled', disabled), ('pressed', pressed),
                         ('active', hover), ('focus', focused),
                         border=radius, sticky='nsew')
    style.layout(name + '.TButton', [(element, {'sticky': 'nsew', 'children': [
        ('Button.padding', {'sticky': 'nsew', 'children': [
            ('Button.label', {'sticky': 'nsew'})]})]})])
    style.configure(name + '.TButton', padding=padding, foreground=foreground,
                    anchor=anchor, font=('Segoe UI', 10), borderwidth=0)
    style.map(name + '.TButton', foreground=[('disabled', '#777780')])


def configure_theme(root):
    root.configure(background=CANVAS)
    root.option_add('*TCombobox*Listbox.background', SURFACE)
    root.option_add('*TCombobox*Listbox.foreground', INK)
    root.option_add('*TCombobox*Listbox.selectBackground', SELECT)
    root.option_add('*TCombobox*Listbox.selectForeground', INK)
    root.option_add('*TCombobox*Listbox.font', ('Segoe UI', 10))
    style = ttk.Style(root)
    style.theme_use('clam')
    style.configure('.', font=('Segoe UI', 10), background=PANEL, foreground=INK,
                    fieldbackground=SURFACE, bordercolor=LINE, lightcolor=LINE,
                    darkcolor=LINE, arrowcolor=MUTED, insertcolor=INK, focuscolor=ACCENT)
    root._graphite_images = []
    tile = _tile(root, PANEL, 12)
    root._graphite_images.append(tile)
    style.element_create('Card.surface', 'image', tile, border=12, sticky='nsew')
    style.layout('Card.TFrame', [('Card.surface', {'sticky': 'nsew'})])
    style.configure('Card.TFrame', background=PANEL)
    style.configure('Sash', sashthickness=7, gripcount=0)
    style.configure('TPanedwindow', background=CANVAS)
    style.configure('Canvas.TFrame', background=CANVAS)
    style.configure('Canvas.TLabel', background=CANVAS, foreground=MUTED)
    style.configure('Header.TFrame', background=HEADER)
    style.configure('Brand.TLabel', background=HEADER, foreground=INK, font=('Segoe UI Semibold', 13))
    style.configure('NavCaption.TLabel', background=HEADER, foreground=MUTED, font=('Segoe UI', 9))
    style.configure('WorkspaceTitle.TLabel', background=CANVAS, foreground=INK, font=('Segoe UI Semibold', 18))
    style.configure('Section.TLabel', foreground=MUTED, font=('Segoe UI Semibold', 9))
    style.configure('Scan.Horizontal.TProgressbar', background=ACCENT, troughcolor=RAISED,
                    borderwidth=0, thickness=4, lightcolor=ACCENT, darkcolor=ACCENT)
    style.configure('Title.TLabel', font=('Segoe UI Semibold', 13))
    for level, color in SEVERITY_COLORS.items():
        style.configure(level + '.Title.TLabel', foreground=color)
    style.configure('Muted.TLabel', foreground=MUTED)
    style.configure('TEntry', padding=(8, 4), borderwidth=1, relief='flat')
    style.configure('TCombobox', padding=(8, 4), borderwidth=1, relief='flat',
                    selectbackground=SELECT, selectforeground=INK)
    style.map('TEntry', bordercolor=[('focus', '#777780')])
    style.map('TCombobox', fieldbackground=[('readonly', SURFACE)],
              bordercolor=[('focus', '#777780')], selectbackground=[('readonly', SURFACE)])
    _rounded_button(root, style, 'Soft', (RAISED, '#39393f', '#222227', SURFACE, RAISED), (11, 5))
    style.layout('TButton', style.layout('Soft.TButton'))
    style.configure('TButton', padding=(11, 5), foreground=INK)
    style.map('TButton', foreground=[('disabled', '#777780')])
    _rounded_button(root, style, 'Nav', (HEADER, RAISED, SURFACE, HEADER, RAISED), (10, 6), anchor='w')
    _rounded_button(root, style, 'Primary', (ACCENT, '#eeeef2', '#bcbcc4', RAISED, ACCENT),
                    (13, 5), foreground='#1b1b20')
    style.configure('Treeview', background=SURFACE, fieldbackground=SURFACE, rowheight=25,
                    borderwidth=0, relief='flat')
    style.configure('Treeview.Heading', background=PANEL, foreground=MUTED,
                    font=('Segoe UI Semibold', 9), padding=(8, 4), relief='flat', borderwidth=0)
    style.map('Treeview', background=[('selected', SELECT)], foreground=[])
    style.map('Treeview.Heading', background=[('active', RAISED)])
    style.configure('Vertical.TScrollbar', troughcolor=SURFACE, background='#414147',
                    arrowsize=10, bordercolor=SURFACE, lightcolor=SURFACE, darkcolor=SURFACE,
                    gripcount=0, borderwidth=0, relief='flat')
    style.configure('TNotebook', borderwidth=0, tabmargins=(0, 0, 0, 3))
    style.configure('TNotebook.Tab', padding=(12, 5), borderwidth=0,
                    bordercolor=PANEL, lightcolor=PANEL, darkcolor=PANEL)
    style.map('TNotebook.Tab', background=[('selected', RAISED), ('active', '#303035'), ('!selected', PANEL)],
              foreground=[('selected', INK), ('!selected', MUTED)])
    style.configure('TCheckbutton', padding=(3, 1))
    style.configure('TRadiobutton', padding=(3, 1))
    style.configure('TSeparator', background=LINE)


def detail_box(parent, height=8):
    return tk.Text(parent, height=height, wrap='word', background=SURFACE, foreground=INK,
                   selectbackground=SELECT, selectforeground=INK, relief='flat',
                   highlightthickness=1, highlightbackground=LINE, highlightcolor='#777780',
                   font=('Segoe UI', 10), padx=10, pady=8, spacing1=2, spacing3=3)


def scrollable(parent, widget):
    scrollbar = ttk.Scrollbar(parent, orient='vertical', command=widget.yview)
    widget.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side='right', fill='y')
    widget.pack(side='left', fill='both', expand=True)
