"""Remove scheduled callbacks before Tk destroys their Python commands."""
import tkinter as tk


def watch_poll(window):
    def destroyed(event):
        if event.widget is window:
            timer = getattr(window, 'poll_timer', None)
            if timer is not None:
                try:
                    window.after_cancel(timer)
                except tk.TclError:
                    pass
    window.bind('<Destroy>', destroyed, add='+')
