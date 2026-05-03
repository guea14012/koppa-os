"""KOPPA stdlib: log — coloured terminal output"""
import sys as _sys

_R = "\033[91m"; _G = "\033[92m"; _Y = "\033[93m"
_C = "\033[96m"; _D = "\033[2m";  _B = "\033[1m"; _E = "\033[0m"

def ok(msg):   print(f"{_G}[+]{_E} {msg}")
def err(msg):  print(f"{_R}[-]{_E} {msg}")
def warn(msg): print(f"{_Y}[!]{_E} {msg}")
def info(msg): print(f"{_C}[*]{_E} {msg}")
def muted(msg):print(f"{_D}{msg}{_E}")
def bold(msg): print(f"{_B}{msg}{_E}")
def raw(msg):  print(msg)
