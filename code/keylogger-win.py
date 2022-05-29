import pynput
import time
from pynput.keyboard import Key, Listener


is_ctrl = False
path = 'e:/file.log'


def press_elem(event):
    event = str(event)
    check = event.find('Key')
    if check != -1:
        event = event.replace('Key.', '')
    with open(path, 'a+') as f:
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
  with open(path, 'a+') as f:
    f.write('{}\n'.format(time.ctime()))
  with Listener(on_press = press_elem, on_release = release_elem) as listener:
    listener.join()