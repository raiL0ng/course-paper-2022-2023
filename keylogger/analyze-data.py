import numpy as np
import matplotlib.pyplot as plt
import pandas as pd

def get_data(file_name):
  file_ = open(file_name, 'r')
  elems = []
  start_time = []
  end_time = []
  prev = -1
  fl = False
  while True:
    line = file_.readline()
    if not line:
      break
    sep = line.find('-')
    if sep != -1:
      elems.append(line[:sep].strip("'"))
      line = line[sep + 1:]
      sep = line.find(':')
      start_time.append(float(line[:sep]))
      end_time.append(float(line[sep + 1:]))
      prev += 1
    elif fl == False:
      start_time.append(0.0)
      # end_time.append(0.0)
      prev += 1
      fl = True
    elif elems != []:
      break
  
  return elems, start_time, end_time
  # time = []
  # for i in range(1, len(time)):
  #   time.append(end_time[i] - start_time[i])
  # return elems, time[:len(time) - 1]
  
def create_diagram(events, data_time, frst, scnd):
  df = pd.DataFrame({frst : data_time[frst], scnd : data_time[scnd]}, index=events)
  ax = df.plot.bar(rot = 0)

  plt.title("Гистограмма") 
  plt.show()

def mode():
  print('Построить гистограмму? (Нажмите "1"))')
  bl = input()
  if bl == '1': 
    name = 'Пользователь №'
    print(f'Выберите два файла для построения (1-{n})')
    s = input()
    frst, scnd = s[:s.find(' ')], s[s.find(' ') + 1:]
    create_diagram(data_events[name + frst], data_time, name + frst, name + scnd)
    return True
  else:
    return False



if __name__ == '__main__':
  print('Введите количество файлов для анализа')
  n = int(input())
  data_events = {}
  data_start_time = {}
  data_end_time = {}
  name = 'Пользователь №'
  for i in range(n):
    print(f'Введие название {i + 1}-го файла (формат <имя_файла>.log):')
    file_name = input()
    data_events[name + str(i + 1)], data_start_time[name + str(i + 1)], \
    data_end_time[name + str(i + 1)] = get_data(file_name)
  fl = True
  while fl:
    fl = mode()