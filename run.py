import sys


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if not args or args == ['--desktop']:
        try:
            import tkinter
        except ImportError as exc:
            reason = str(exc)
        else:
            from sentinel.app import DesktopUnavailable, main as desktop
            try:
                return desktop()
            except DesktopUnavailable as exc:
                reason = str(exc)
        message = f'Sentinel desktop requires a working Tcl/Tk installation. {reason}'
        if args:
            raise SystemExit(message)
        print(message + '\nOpening the local browser dashboard.', file=sys.stderr)

    from sentinel.web import main as web
    return web(args[1:] if args[:1] == ['--web'] else args)


if __name__ == '__main__':
    main()
