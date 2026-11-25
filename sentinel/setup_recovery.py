"""Plain-language next steps after an explicit setup operation.

No automatic restarts, installation retries or application launches.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Recovery:
    heading: str
    instruction: str
    retry: bool = False


def recovery(result):
    status = result.get('status')
    if status == 'completed':
        return Recovery('Setup finished', 'Check the updated tool status. Detection does not guarantee a successful assessment.')
    if status == 'cancelled':
        return Recovery('Setup stopped', 'Installed components are kept. You can continue setup whenever you are ready.', True)
    actions = {
        'restart_app': Recovery('Restart Sentinel', 'Finish any installer prompts, close Sentinel and open it again. If Windows asks for a restart, restart Windows first. Then retry setup.'),
        'start_docker': Recovery('Start Docker Desktop', 'Open Docker Desktop from the Start menu. Finish any first-run prompts, wait for the Linux engine to start, then retry setup.', True),
        'restore_files': Recovery('Restore Sentinel files', 'Use a complete Sentinel source checkout or reinstall from the official Sentinel package. Then retry setup.'),
        'retry': Recovery('Try setup again', 'Check your internet connection and make sure Docker Desktop is running. Retry when ready.', True),
    }
    return actions.get(result.get('next_action'),
                       Recovery('Setup needs attention', 'Read the setup message, finish any installer prompts, and retry if appropriate.', True))
