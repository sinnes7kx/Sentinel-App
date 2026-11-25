"""Remove scheduled callbacks before Tk destroys their Python commands."""
import tkinter as tk


def watch_variables(window, variables, callback):
    """Keep Tk variable traces for exactly as long as their owning window."""
    traces = [(variable, variable.trace_add('write', callback)) for variable in variables]

    def destroyed(event):
        if event.widget is window:
            for variable, trace in traces:
                variable.trace_remove('write', trace)

    window.bind('<Destroy>', destroyed, add='+')


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
