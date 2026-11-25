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


def watch_authorized_scope(window, variables, authorization):
    """Keep explicit permission only while the exact UI scope stays unchanged.

    Same-value writes (e.g. refreshing the current project after a scan) are
    not scope changes. Once a value changes, returning to the old value does
    not restore permission. The checkbox is always user-revocable.
    """
    previous = tuple(variable.get() for variable in variables)

    def changed(*_):
        nonlocal previous
        current = tuple(variable.get() for variable in variables)
        if current != previous:
            previous = current
            authorization.set(False)

    watch_variables(window, variables, changed)


def bind_escape(window, close=None):
    """Escape uses the same close action as the window manager."""
    action = close or window.destroy
    def escape(_event):
        action()
        return 'break'
    window.bind('<Escape>', escape, add='+')
