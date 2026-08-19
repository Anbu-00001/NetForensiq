#!/usr/bin/env python3
"""Verify the interface palette, from the source rather than from memory.

Two failures this exists to prevent, both of which have actually happened:

  A colour that cannot be read.  #00D4FF measures 10.52:1 on the old navy and
  1.77:1 on white.  Nothing about the hex says which, so a value carried over
  from a dark design lands on a light one and looks fine to the author on their
  own monitor.  Every token below is recomputed against both grounds on every
  run, from the constants in tokens.js -- not from a table someone updated by
  hand.

  A colour that is not in the palette at all.  Sixteen files once carried a
  hardcoded accent, so changing the theme changed nothing on screen. Any
  literal in the frontend whose RGB does not match a declared token is
  reported here with its file and line.

Run:  python3 scripts/check_palette.py
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOKENS = ROOT / 'frontend' / 'src' / 'theme' / 'tokens.js'
SRC = ROOT / 'frontend' / 'src'

AA_NORMAL = 4.5   # WCAG 2.1 AA, normal-size text
AA_LARGE = 3.0    # AA for large text, and the floor for graphical objects

# Tokens that carry text. Everything else is a ground, a rule or a fill, and is
# held to the graphical-object floor instead.
TEXT_TOKENS = {
    'INK', 'INK_SOFT', 'GREY', 'GREY_MUTED', 'CYAN',
    'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INTACT',
}
# CYAN_BRIGHT is legible only on ink and is checked against that ground alone.
INK_GROUND_TOKENS = {'CYAN_BRIGHT'}


def luminance(hex_colour):
    h = hex_colour.lstrip('#')
    channels = [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
              for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast(a, b):
    la, lb = luminance(a), luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def read_tokens():
    """Parse `export const NAME = '#RRGGBB';` and one-level aliases."""
    text = TOKENS.read_text()
    values, aliases = {}, {}
    for name, value in re.findall(r"export const (\w+) = '(#[0-9A-Fa-f]{6})'", text):
        values[name] = value.upper()
    for name, target in re.findall(r'export const (\w+) = ([A-Z_]+);', text):
        aliases[name] = target
    for name, target in aliases.items():
        if target in values:
            values[name] = values[target]
    return values


def check_contrast(tokens):
    # Three grounds, not two. The original pair missed PANEL_ALT — the table
    # stripe and chip ground — where GREY_MUTED measured 4.24:1 and failed,
    # while passing on both grounds this function was checking. The browser
    # suite caught it; this now catches it first.
    paper, panel, ink = tokens['PAPER'], tokens['PANEL'], tokens['INK']
    panel_alt = tokens['PANEL_ALT']
    problems = []
    for name, value in sorted(tokens.items()):
        if name in INK_GROUND_TOKENS:
            ratio = contrast(value, ink)
            if ratio < AA_NORMAL:
                problems.append(f'{name} ({value}) is {ratio:.2f}:1 on INK, needs {AA_NORMAL}')
            continue
        if name not in TEXT_TOKENS:
            continue
        for ground_name, ground in (('PAPER', paper), ('PANEL', panel),
                                    ('PANEL_ALT', panel_alt)):
            ratio = contrast(value, ground)
            if ratio < AA_NORMAL:
                problems.append(
                    f'{name} ({value}) is {ratio:.2f}:1 on {ground_name} ({ground}), '
                    f'needs {AA_NORMAL} for text')
    return problems


LITERAL = re.compile(r'#[0-9A-Fa-f]{6}\b|rgba?\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*(?:,\s*[\d.]+\s*)?\)')


def approved_rgb(tokens):
    rgb = set()
    for value in tokens.values():
        h = value.lstrip('#')
        rgb.add(tuple(int(h[i:i + 2], 16) for i in (0, 2, 4)))
    # Pure black and pure white at any alpha: legitimate for scrims and rings.
    rgb.add((0, 0, 0))
    rgb.add((255, 255, 255))
    return rgb


def to_rgb(literal):
    if literal.startswith('#'):
        h = literal[1:]
        return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))
    parts = re.findall(r'[\d.]+', literal)
    return tuple(int(float(p)) for p in parts[:3])


def check_literals(tokens):
    allowed = approved_rgb(tokens)
    strays = []
    for path in sorted(SRC.rglob('*')):
        if path.suffix not in ('.jsx', '.js') or path.name == 'tokens.js':
            continue
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            for literal in LITERAL.findall(line):
                if to_rgb(literal) not in allowed:
                    rel = path.relative_to(ROOT)
                    strays.append(f'{rel}:{lineno}  {literal}')
    return strays


def main():
    tokens = read_tokens()
    if 'PAPER' not in tokens:
        print('could not parse tokens.js', file=sys.stderr)
        return 2

    contrast_problems = check_contrast(tokens)
    strays = check_literals(tokens)

    print(f'{len(tokens)} tokens declared')
    for name in sorted(TEXT_TOKENS):
        value = tokens[name]
        print(f'  {name:<11} {value}  paper {contrast(value, tokens["PAPER"]):5.2f}:1'
              f'  panel {contrast(value, tokens["PANEL"]):5.2f}:1'
              f'  alt {contrast(value, tokens["PANEL_ALT"]):5.2f}:1')
    bright = tokens.get('CYAN_BRIGHT')
    if bright:
        print(f'  {"CYAN_BRIGHT":<11} {bright}  ink   '
              f'{contrast(bright, tokens["INK"]):5.2f}:1  '
              f'(paper {contrast(bright, tokens["PAPER"]):.2f}:1 — dark strips only)')

    if contrast_problems:
        print('\nCONTRAST FAILURES')
        for problem in contrast_problems:
            print(f'  {problem}')
    if strays:
        print(f'\nOFF-PALETTE LITERALS ({len(strays)})')
        for stray in strays:
            print(f'  {stray}')

    if contrast_problems or strays:
        return 1
    print('\nAll tokens meet WCAG 2.1 AA and no off-palette literal is in use.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
