import itertools 
import sys 
import time 


def spin_loader(stop_event):
    spinner = itertools.cycle(['|', '-'])

    while not stop_event.is_set():
        sys.stdout.write(f"\rLoading {next(spinner)}")
        sys.stdout.flush()
        time.sleep(0.1)

    sys.stdout.write('\r' + ' ' * 20 + '\r')
    sys.stdout.flush()

