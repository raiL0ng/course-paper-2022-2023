# import pynput
# import os
# import time
# from pynput.keyboard import Key, Listener, HotKey

# log_file_elems = os.environ.get( 'pylogger_file',
# 	            				           os.path.expanduser('~/elems.log')
#                       			   )

# log_file_time = os.environ.get( 'pylogger_file',
# 	            				           os.path.expanduser('~/time.log')
#                      			    )

# keys = []

# def press_elem(event):
#     print('{}\n'.format(event))
#     print(type(event))
#     check = str(event).find('Key')
#     if check != -1:
# 	  	  event = str(event).replace('Key.', '')
#     keys.append(event)
#     with open(log_file_time, 'a+') as ft:
#         ft.write('{}\n'.format(time.time()))
#     with open(log_file_elems, 'a+') as f:
#         f.write('{}\n'.format(event))


# def release_elem(event):
#     for el in keys:
#         print(el, end=' ')
#     print('')
#     print('{}\n'.format(event))

# def aux_func(f):
#     return lambda k: f(listener.canonical(hotkey(k)))


# def stop_listen():
#     exit()


# # with GlobalHotKeys({'<ctrl>+<k>' : stop_listen}) as act:
# #     act.join()

# if __name__ == '__main__':
#     hotkey = HotKey(HotKey.parse('<ctrl>+k'), stop_listen)

#     with open(log_file_time, 'a+') as ft:
# 	  	  ft.write('{}\n'.format(time.ctime()))
#     with open(log_file_elems, 'a+') as f:
#         f.write('{}\n'.format(time.ctime()))
#     with Listener(on_press = press_elem, on_release = aux_func(hotkey.release_elem)) as listener:
# 	  	  listener.join()

# import pynput
# from pynput.keyboard import Key, Listener, HotKey

# def on_activate():
#     Listener.stop()

# def for_canonical(f):
#     return lambda k: f(l.canonical(k))

# is_ctrl = False


# def press_el(event):
#     print(event)

# def release(event):
#     global is_ctrl
#     if event == Key.ctrl:
#         is_ctrl = True
#     if event != Key.ctrl and event != Key.f5:
#         is_ctrl = False
#     if event == Key.f5 and is_ctrl:
#         return False

# # определение горячей клавиши
# hotkey = HotKey(
#     HotKey.parse('<ctrl>+<alt>+h'),
#     on_activate)


# if __name__ == '__main__':
#     with Listener(on_press=press_el, on_release = release) as l:
#         l.join()
#     # with Listener(
#     #         on_press = for_canonical(hotkey.release), on_release = for_canonical(hotkey.release)) as h:
#     #     h.join()


import pynput
import os
import time
from pynput.keyboard import Key, Listener

log_file_elems = os.environ.get( 'pylogger_file',
	            				           os.path.expanduser('~/file.log')
                      			   )

# log_file_time = os.environ.get( 'pylogger_file',
	            				        #    os.path.expanduser('~/time.log')
                     			    # )

keys = []
is_ctrl = False

def press_elem(event):
    event = str(event)
    check = event.find('Key')
    if check != -1:
	  	  event = event.replace('Key.', '')
    keys.append(event)
    # with open(log_file_time, 'a+') as ft:
    #     ft.write('{}\n'.format(time.time()))
    with open(log_file_elems, 'a+') as f:
        f.write('{}-'.format(event))
        f.write('{}\n'.format(time.time()))
    


def release_elem(event):
    # for el in keys:
    #     print(el, end=' ')
    # print('')
    global is_ctrl
    if event == Key.ctrl:
        is_ctrl = True
    if event != Key.ctrl and event != Key.f5:
        is_ctrl = False
    if event == Key.f5 and is_ctrl:
        return False    


if __name__ == '__main__':
    with open(log_file_elems, 'a+') as f:
        f.write('{}\n'.format(time.ctime()))
    with Listener(on_press = press_elem, on_release = release_elem) as listener:
	  	  listener.join()