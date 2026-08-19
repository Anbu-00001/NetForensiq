"""
Whether this process can actually capture packets, asked before it tries.

Why this is worth a module
--------------------------
Scapy's `sniff()` without CAP_NET_RAW does not raise. It returns, having
captured nothing, and the capture reports zero packets and zero findings. On a
terminal that reads as "there was no traffic" — a wrong answer that looks like
a right one, and the single worst way for a live capture to fail during a
demonstration or an investigation.

So the question is asked up front, by opening the raw socket scapy would open,
and the answer is a sentence the operator can act on rather than an empty table.
"""

import socket

MESSAGE = (
    'Packet capture needs raw-socket access, which this process does not have.\n'
    '\n'
    'Without it scapy captures nothing and reports no error — the capture would\n'
    'finish claiming zero packets, which is indistinguishable from a quiet\n'
    'network.\n'
    '\n'
    'Either run this command under sudo, or grant the capability once so it is\n'
    'not needed again:\n'
    '\n'
    '    sudo setcap cap_net_raw,cap_net_admin=eip \\\n'
    '        "$(readlink -f backend/.venv/bin/python)"\n'
    '\n'
    'The capability is narrower than sudo: it permits packet capture and\n'
    'nothing else. Reading a stored .pcap needs none of this.'
)


def can_capture():
    """(ok, reason). Never raises — callers may want to report rather than stop."""
    try:
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 3).close()
    except PermissionError:
        return False, MESSAGE
    except AttributeError:
        # AF_PACKET is Linux-only. Elsewhere the question cannot be asked this
        # way, so it is not answered — claiming success would be a guess.
        return True, ''
    except OSError as exc:
        return False, f'{MESSAGE}\n\nThe underlying error was: {exc}'
    return True, ''
