"""KOPPA stdlib: time — time and timing utilities."""
import time as _time, datetime


def now_ms():
    return int(_time.time() * 1000)

def now():
    return _time.time()

def sleep(ms):
    _time.sleep(ms / 1000.0)

def timestamp():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def date():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d")

def epoch():
    return int(_time.time())

def from_epoch(ts):
    return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

def elapsed_ms(start_ms):
    return now_ms() - start_ms

def stopwatch():
    """Return a start time in ms."""
    return now_ms()
