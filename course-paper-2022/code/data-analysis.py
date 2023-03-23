import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import time
from colorama import init, Back, Fore

init(autoreset=True)
FileName = ''
Packet_list = []
Object_list = []
Labels_list = []
x_axisLabels = []

# Класс, содержащий информацию о каком-либо пакете
class PacketInf:

  def __init__( self, numPacket, timePacket, packetSize, mac_src, mac_dest, protoType
              , ip_src, ip_dest, port_src, port_dest, len_data, data
              , seq=None, ack=None, fl_ack=None, fl_psh=None, fl_syn=None):
    self.numPacket = int(numPacket)
    self.timePacket = float(timePacket)
    self.packetSize = int(packetSize)
    self.mac_src = mac_src
    self.mac_dest = mac_dest
    self.ip_src = ip_src
    self.ip_dest = ip_dest
    self.port_src = port_src
    self.port_dest = port_dest
    self.len_data = int(len_data)
    self.data = data
    self.protoType = protoType
    self.seq = seq
    self.ack = ack
    self.fl_ack = fl_ack
    self.fl_psh = fl_psh
    self.fl_syn = fl_syn


# Класс, содержащий информацию относительно какого-либо IP-адреса
class ExploreObject:

  def __init__(self, ip):
    self.ip = ip
    self.strt_time = None
    self.fin_time = None
    self.amnt_packet = None
    self.avg_packet_num = None
    self.avg_packet_size = None

    self.in_out_rel_data = None
    self.ack_flags_diff_data = None
    self.udp_tcp_rel_data = None
    self.syn_flags_freq_data = None
    self.psh_flags_freq_data = None
    self.adjcIPList = None
    self.adjcPacketList = None


# Считывание с файла и заполнение массива
# Packet_list объектами класса PacketInf
def read_from_file(inf):
  a = []
  while True:
    beg = inf.find(':')
    end = inf.find(';')
    if beg == -1 and end == -1:
      break
    else:
      a.append(inf[beg + 1: end])
    inf = inf[end + 1:]
  try:
    if a[5] == 'TCP':
      Packet_list.append(PacketInf( a[0], a[1], a[2], a[3], a[4], a[5]
                                  , a[6], a[7], a[8], a[9], a[15], a[16]
                                  , a[10], a[11], a[12], a[13], a[14] ))
    elif a[5] == 'UDP':
      Packet_list.append(PacketInf( a[0], a[1], a[2], a[3], a[4], a[5]
                                  , a[6], a[7], a[8], a[9], a[10], a[11] ))
  except:
    print('Ошибка при считывании файла...')
    exit(0)

# Получение общей информации о текущей
# попытке перехвата трафика
def get_common_data():
  IPList = []
  numPacketsPerSec = []
  curTime = Packet_list[0].timePacket + 1
  fin = Packet_list[-1].timePacket + 1
  Labels_list.append(time.strftime('%H:%M:%S', time.localtime(Packet_list[0].timePacket)))
  cntPacket = 0
  i = 0
  while curTime < fin:
    for k in range(i, len(Packet_list)):
      if Packet_list[k].timePacket > curTime:
        numPacketsPerSec.append(cntPacket)
        Labels_list.append(time.strftime('%H:%M:%S', time.localtime(curTime)))
        cntPacket = 0
        i = k
        break
      cntPacket += 1
    curTime += 1
  numPacketsPerSec.append(cntPacket)
  for p in Packet_list:
    CurIP = p.ip_src
    if CurIP not in IPList:
      IPList.append(CurIP)
  return IPList, numPacketsPerSec


# Получение данных об отношении входящего
# трафика к исходящему в единицу времени
def get_in_out_rel(exploreIP, strt, fin):
  cntInput = 0
  cntOutput = 0
  rel_list = []
  curTime = strt + 1
  fin += 1
  pos = 0
  while curTime < fin:
    for k in range(pos, len(Packet_list)):
      if Packet_list[k].timePacket > curTime:
        if cntOutput != 0:
          rel_list.append(cntInput / cntOutput)
        else:
          rel_list.append(0.0)
        cntInput = 0
        cntOutput = 0
        pos = k
        break
      if Packet_list[k].ip_src == exploreIP:
        cntOutput += 1
      if Packet_list[k].ip_dest == exploreIP:
        cntInput += 1
    curTime += 1
  if cntOutput != 0:
    rel_list.append(cntInput / cntOutput)
  else:
    rel_list.append(0.0)
  return rel_list


# Получение данных о разности количества
# исходящих ACK-флагов и количества входящих
# ACK-флагов
def get_ack_flags_diff(exploreIP, strt, fin):
  cntInput = 0
  cntOutput = 0
  diff_list = []
  curTime = strt + 1
  fin += 1
  pos = 0
  while curTime < fin:
    for k in range(pos, len(Packet_list)):
      if Packet_list[k].timePacket > curTime:
          diff_list.append(cntOutput - cntInput)
          cntInput = 0
          cntOutput = 0
          pos = k
          break
      if Packet_list[k].protoType == 'TCP' and Packet_list[k].fl_ack == '1':
        if Packet_list[k].ip_src == exploreIP:
          cntOutput += 1
        if Packet_list[k].ip_dest == exploreIP:
          cntInput += 1
    curTime += 1
  diff_list.append(cntOutput - cntInput)
  return diff_list


# Получение данных об отношении количества
# входящего UDP-трафика на количество
# исходящего TCP-трафика в единицу времени
def get_udp_tcp_rel(exploreIP, strt, fin):
  cntUDP = 0
  cntTCP = 0
  curTime = strt + 1
  fin += 1
  pos = 0
  rel_list = []
  while curTime < fin:
    for k in range(pos, len(Packet_list)):
      if Packet_list[k].timePacket > curTime:
        if cntTCP != 0:
          rel_list.append(cntUDP / cntTCP)
        else:
          rel_list.append(0.0)
        cntTCP = 0
        cntUDP = 0
        pos = k
        break
      if Packet_list[k].ip_dest == exploreIP:
        if Packet_list[k].protoType == 'TCP':
          cntTCP += 1
        if Packet_list[k].protoType == 'UDP':
          cntUDP += 1
    curTime += 1
  if cntTCP != 0:
    rel_list.append(cntUDP / cntTCP)
  else:
    rel_list.append(0.0)
  return rel_list


# Получение данных о частоте SYN-флагов
def get_syn_flags_freq(exploreIP, strt, fin):
  cntSynTCP = 0
  cntTCP = 0
  rel_list = []
  curTime = strt + 1
  fin += 1
  pos = 0
  while curTime < fin:
    for k in range(pos, len(Packet_list)):
      if Packet_list[k].timePacket > curTime:
        if cntTCP != 0:
          rel_list.append(cntSynTCP / cntTCP)
        else:
          rel_list.append(0.0)
        cntSynTCP = 0
        cntTCP = 0
        pos = k
        break
      if Packet_list[k].ip_dest == exploreIP and Packet_list[k].protoType == 'TCP':
        if Packet_list[k].fl_syn == '1':
          cntSynTCP += 1
        else:
          cntTCP += 1
    curTime += 1
  if cntTCP != 0:
    rel_list.append(cntSynTCP / cntTCP)
  else:
    rel_list.append(0.0)
  return rel_list


# Получение данных о частоте PSH-флагов
def get_psh_flags_freq(exploreIP, strt, fin):
  cntPshTCP = 0
  cntTCP = 0
  rel_list = []
  curTime = strt + 1
  fin += 1
  pos = 0
  while curTime < fin:
    for k in range(pos, len(Packet_list)):
      if Packet_list[k].timePacket > curTime:
        if cntTCP != 0:
          rel_list.append(cntPshTCP / cntTCP)
        else:
          rel_list.append(0.0)
        cntPshTCP = 0
        cntTCP = 0
        pos = k
        break
      if Packet_list[k].ip_dest == exploreIP and Packet_list[k].protoType == 'TCP':
        if Packet_list[k].fl_psh == '1':
          cntPshTCP += 1
        else:
          cntTCP += 1
    curTime += 1
  if cntTCP != 0:
    rel_list.append(cntPshTCP / cntTCP)
  else:
    rel_list.append(0.0)
  return rel_list


# Получение общей информации о трафике,
# связанном с выбранным IP-адресом
def get_inf_about_IP(exploreIP):
  adjcPacketList = []
  adjcIPList = []
  for p in Packet_list:
    if p.ip_src == exploreIP:
      adjcPacketList.append(p)
      adjcIPList.append(p.ip_dest)
    if p.ip_dest == exploreIP:
      adjcPacketList.append(p)
      adjcIPList.append(p.ip_src)
  return adjcPacketList, adjcIPList


# Вывод пакетов, связанных с выбранным IP-адресом 
def print_adjacent_packets(adjcPacketLIst):
  cnt = 0
  for p in adjcPacketLIst:
    t = time.strftime('%H:%M:%S', time.localtime(p.timePacket))
    if cnt % 2 == 1:
      print( f'Номер пакета: {p.numPacket};', f'Время: {t};'
           , f'Размер: {p.packetSize};', f'MAC-адрес отправителя: {p.mac_src};'
           , f'MAC-адрес получателя: {p.mac_dest};'
           , f'IP-адрес отправителя: {p.ip_src};', f'IP-адрес получателя: {p.ip_dest};'
           , f'Протокол: {p.protoType};', f'Порт отправителя: {p.port_src};'
           , f'Порт получателя: {p.port_dest};', f'Количество байт: {p.len_data};' )
    else:
      print( Back.CYAN + Fore.BLACK + f'Номер пакета: {p.numPacket};' + f' Время: {t};' +
             f' Размер: {p.packetSize};' + f' MAC-адрес отправителя: {p.mac_src};' +
             f' MAC-адрес получателя: {p.mac_dest};' +
             f' IP-адрес отправителя: {p.ip_src};' + f' IP-адрес получателя: {p.ip_dest};' +
             f' Протокол: {p.protoType};' + f' Порт отправителя: {p.port_src};' +
             f' Порт получателя: {p.port_dest};' + f' Количество байт: {p.len_data};' )
    cnt += 1


# Вывод пар (число, IP-адрес) для
# предоставления выбора IP-адреса
# пользователю
def print_IP_list(IPList):
  num = 0
  cnt = 1
  for el in IPList:
    if cnt > 3:
      cnt = 0
      print ('[' + str(num), '---', el, end=']\n')
    else:
      print ('[' + str(num), '---', el, end='] ')
    cnt += 1
    num += 1


# Получение меток и "шага" для оси абсцисс
def get_x_labels(total_time):
  step = 1
  if total_time > 500:
    step = 8
  elif total_time > 100:
    step = 5
  elif total_time > 50:
    step = 2
  for i in range(0, len(Labels_list), step):
    x_axisLabels.append(Labels_list[i])
  return step


# Выбор опций для выбранного IP-адреса
def choose_options(k, strt, fin, step):
  curIP = Object_list[k].ip
  if Object_list[k].adjcPacketList == None:
    Object_list[k].adjcPacketList, Object_list[k].adjcIPList = get_inf_about_IP(curIP)
  if Object_list[k].strt_time == None:
    Object_list[k].strt_time = time.localtime(Object_list[k].adjcPacketList[0].timePacket)
  if Object_list[k].fin_time == None:
    Object_list[k].fin_time = time.localtime(Object_list[k].adjcPacketList[-1].timePacket)
  if Object_list[k].amnt_packet == None:
    Object_list[k].amnt_packet = len(Object_list[k].adjcPacketList)
  if Object_list[k].avg_packet_num == None:
    tmp = Object_list[k].adjcPacketList[-1].timePacket - \
          Object_list[k].adjcPacketList[0].timePacket
    if tmp == 0:
      tmp = 1
    Object_list[k].avg_packet_num = round(Object_list[k].amnt_packet / tmp, 3)
  if Object_list[k].avg_packet_size == None:
    avgSize = 0
    for p in Object_list[k].adjcPacketList:
      avgSize += p.len_data
    Object_list[k].avg_packet_size = round(avgSize / Object_list[k].amnt_packet, 3)
  while True:
    print(f'Общая информация о трафике, связанном с {curIP}')
    print( 'Время первого перехваченного пакета: '
         , time.strftime('%d.%m.%Y г. %H:%M:%S', Object_list[k].strt_time) )
    print( 'Время последнего перехваченного пакета: '
         , time.strftime('%d.%m.%Y г. %H:%M:%S', Object_list[k].fin_time) )
    print('Количество пакетов: ', Object_list[k].amnt_packet)
    print('Среднее количество пакетов в секунду: ', Object_list[k].avg_packet_num)
    print('Средний размер пакетов: ', Object_list[k].avg_packet_size)  
    print(f"""Выберите опцию:
    1. Вывести весь трафик, связанный с {curIP}
    2. Построить график отношения входящего и исходящего трафиков
    3. Построить график отношения объема входящего UDP-трафика и объёма входящего TCP-трафика
    4. Построить график разности числа исходящих и числа входящих ACK-флагов в единицу времени
    5. Построить график частоты SYN и PSH флагов во входящих пакетах
    6. Вернуться к выбору IP-адреса """)
    bl = input()
    if bl == '1':
      print_adjacent_packets(Object_list[k].adjcPacketList)
    elif bl == '2':
      if Object_list[k].in_out_rel_data == None:
        data = get_in_out_rel(curIP, strt, fin)
        Object_list[k].in_out_rel_data = data
      x = [i for i in range(0, len(Object_list[k].in_out_rel_data))]
      x_labels = [i for i in range(0, len(x), step)]
      fig = plt.figure(figsize=(16, 6), constrained_layout=True)
      f = fig.add_subplot()
      f.grid()
      f.set_title('Отношение объема входящего к объему исходящего трафиков', fontsize=15)
      f.set_xlabel('Общее время перехвата трафика', fontsize=15)
      plt.plot(x, Object_list[k].in_out_rel_data)
      plt.xticks(x_labels, x_axisLabels, rotation=30)
      plt.show()
    elif bl == '3':
      if Object_list[k].udp_tcp_rel_data == None:
        data = get_udp_tcp_rel(curIP, strt, fin)
        Object_list[k].udp_tcp_rel_data = data
      x = [i for i in range(0, len(Object_list[k].udp_tcp_rel_data))]
      x_labels = [i for i in range(0, len(x), step)]
      fig = plt.figure(figsize=(16, 6), constrained_layout=True)
      f = fig.add_subplot()
      f.grid()
      f.set_title( 'Отношение объема входящего UDP-трафика к объему входящего TCP-трафика'
                 , fontsize=15 )
      f.set_xlabel('Общее время перехвата трафика', fontsize=15)
      plt.plot(x, Object_list[k].udp_tcp_rel_data)
      plt.xticks(x_labels, x_axisLabels, rotation=30)
      plt.show()
    elif bl == '4':
      if Object_list[k].ack_flags_diff_data == None:
        data = get_ack_flags_diff(curIP, strt, fin)
        Object_list[k].ack_flags_diff_data = data
      x = [i for i in range(0, len(Object_list[k].ack_flags_diff_data))]
      x_labels = [i for i in range(0, len(x), step)]
      fig = plt.figure(figsize=(16, 6), constrained_layout=True)
      f = fig.add_subplot()
      plt.plot(x, Object_list[k].ack_flags_diff_data)
      f.grid()
      f.set_title('Разность числа исходящих и числа входящих ACK-флагов', fontsize=15)
      f.set_xlabel('Общее время перехвата трафика', fontsize=15)
      plt.xticks(x_labels, x_axisLabels, rotation=30)
      plt.show()
    elif bl == '5':
      if Object_list[k].syn_flags_freq_data == None:
        data = get_syn_flags_freq(curIP, strt, fin)
        Object_list[k].syn_flags_freq_data = data
      if Object_list[k].psh_flags_freq_data == None:
        data = get_psh_flags_freq(curIP, strt, fin)
        Object_list[k].psh_flags_freq_data = data
      x = [i for i in range(0, len(Object_list[k].syn_flags_freq_data))]
      x_labels = [i for i in range(0, len(x), step)]
      fig = plt.figure(figsize=(16, 6), constrained_layout=True)
      gs = gridspec.GridSpec(ncols=1, nrows=2, figure=fig)
      fig_1 = fig.add_subplot(gs[0, 0])
      fig_1.grid()
      plt.plot(x, Object_list[k].syn_flags_freq_data, 'b')
      plt.xticks(x_labels, x_axisLabels, rotation=30, fontsize=8)
      fig_2 = fig.add_subplot(gs[1, 0])
      fig_2.grid()
      plt.plot(x, Object_list[k].psh_flags_freq_data, 'g')
      plt.xticks(x_labels, x_axisLabels, rotation=30, fontsize=8)
      fig_1.set_title('Частота флагов SYN', fontsize=15)
      fig_1.set_xlabel('Общее время перехвата трафика', fontsize=15)
      fig_2.set_title('Частота флагов PSH', fontsize=15)
      fig_2.set_xlabel('Общее время перехвата трафика', fontsize=15)
      plt.show()
    elif bl == '6':
      break
    
  
if __name__ == '__main__':
  print('Введите название файла (например: data.log)')
  FileName = input()
  while True:
    if not Packet_list:
      try:
        f = open(FileName, 'r')
      except:
        print('Некорректное название файла!')
        exit(0)
      while True:
        inf = f.readline()
        if not inf:
          break
        read_from_file(inf)
      f.close()
      IPList, numPacketsPerSec = get_common_data()
      strt = Packet_list[0].timePacket
      fin = Packet_list[-1].timePacket
      strt_time = time.localtime(strt)
      fin_time = time.localtime(fin)
      avgNumPacket = 0
      for el in numPacketsPerSec:
        avgNumPacket += el
      avgNumPacket /= len(numPacketsPerSec)
      avgSizePacket = 0
      for p in Packet_list:
        avgSizePacket += p.packetSize
      avgSizePacket /= len(Packet_list)
      step = get_x_labels(int(fin - strt))

    print('Общая информация:')
    print( 'Время первого перехваченного пакета: '
         , time.strftime('%d.%m.%Y г. %H:%M:%S', strt_time) )
    print( 'Время последнего перехваченного пакета: '
         , time.strftime('%d.%m.%Y г. %H:%M:%S', fin_time) )
    print('Количество пакетов: ', len(Packet_list))
    print('Общее время перехвата: ', round(fin - strt, 3), 'сек')
    print('Среднее количество пакетов в секунду: ', round(avgNumPacket, 3))
    print('Средний размер пакетов: ', round(avgSizePacket, 3))
    print('Завершить просмотр (нажмите \"q\" для выхода)')
    for k in range(0, len(IPList)):
      Object_list.append(ExploreObject(IPList[k]))
    print_IP_list(IPList)
    print(f'\nВыберите цифру (0 - {len(IPList) - 1}) для просмотра IP-адреса:')
    k = input()
    if k == 'q':
      break
    try:
      k = int(k)
    except:
      print('Некорректный ввод')
    else:
      if 0 <= k < len(IPList):
        choose_options(k, strt, fin, step)
      else:
        print(f'Введите число в пределах 0 - {len(IPList) - 1}')