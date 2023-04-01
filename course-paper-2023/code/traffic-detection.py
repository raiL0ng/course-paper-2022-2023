import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import time, socket, os, struct, keyboard
from colorama import init, Back, Fore

init(autoreset=True)
FileName = ''
Packet_list = []
Object_list = []
Labels_list = []
x_axisLabels = []
line = '-------------------------'

# Класс, содержащий информацию о каком-либо пакете
class PacketInf:

  def __init__( self, numPacket, timePacket, packetSize, mac_src, mac_dest, protoType
              , ip_src, ip_dest, port_src, port_dest, len_data, seq=None, ack=None
              , fl_ack=None, fl_psh=None, fl_rst=None, fl_syn=None, fl_fin=None):
    self.numPacket = int(numPacket)
    self.timePacket = float(timePacket)
    self.packetSize = int(packetSize)
    self.mac_src = mac_src
    self.mac_dest = mac_dest
    self.protoType = protoType
    self.ip_src = ip_src
    self.ip_dest = ip_dest
    self.port_src = port_src
    self.port_dest = port_dest
    self.len_data = int(len_data)
    self.seq = seq
    self.ack = ack
    self.fl_ack = fl_ack
    self.fl_psh = fl_psh
    self.fl_rst = fl_rst
    self.fl_syn = fl_syn
    self.fl_fin = fl_fin


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


# Получение ethernet-кадра
def get_ethernet_frame(data):
  dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
  return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto)


# Получение MAC-адреса
def get_mac_addr(mac_bytes):
  mac_str = ''
  for el in mac_bytes:
    mac_str += format(el, '02x').upper() + ':'
  return mac_str[:len(mac_str) - 1]


# Получение IPv4-заголовка
def get_ipv4_data(data):
  version_header_length = data[0]
  header_length = (version_header_length & 15) * 4
  ttl, proto, src, dest = struct.unpack('!8xBB2x4s4s', data[:20])
  return ttl, proto, ipv4_dec(src), ipv4_dec(dest), data[header_length:]


# Получение IP-адреса формата X.X.X.X
def ipv4_dec(ip_bytes):
  ip_str = ''
  for el in ip_bytes:
    ip_str += str(el) + '.'
  return ip_str[:-1]


# Получение UDP-сегмента данных
def get_udp_segment(data):
  src_port, dest_port, size = struct.unpack('!HH2xH', data[:8])
  return str(src_port), str(dest_port), size, data[8:]


# Получение TCP-cегмента данных
def get_tcp_segment(data):
  src_port, dest_port, sequence, ack, some_block = struct.unpack('!HHLLH', data[:14])
  return str(src_port), str(dest_port), str(sequence), str(ack), \
         some_block, data[(some_block >> 12) * 4:]


# Форматирование данных для корректного представления
def format_data(data):
  if isinstance(data, bytes):
    data = ''.join(r'\x{:02x}'.format(el) for el in data)
  return data


# Перехват трафика и вывод информации в консоль
def start_to_listen(s_listen, f=-1):
  NumPacket = 1
  while True:
    # Получение пакетов в виде набора hex-чисел
    raw_data, _ = s_listen.recvfrom(65565)
    pinf = [''] * 18
    pinf[0], pinf[1] = NumPacket, time.time()
    pinf[2] = len(raw_data)
    # Если это интернет-протокол четвертой версии    
    pinf[4], pinf[3], protocol = get_ethernet_frame(raw_data)
    if protocol == 8:
      NumPacket += 1
      _, proto, pinf[6], pinf[7], data_ipv4 = get_ipv4_data(raw_data[14:])
      # Если это UDP-протокол  
      if proto == 17:
        pinf[5] = 'UDP'
        pinf[8], pinf[9], _, data_udp = get_udp_segment(data_ipv4)
        pinf[10] = len(data_udp)
        Packet_list.append(PacketInf( pinf[0], pinf[1], pinf[2]
                                    , pinf[3], pinf[4], pinf[5]
                                    , pinf[6], pinf[7], pinf[8]
                                    , pinf[9], pinf[10]))
        print_packet_inf(Packet_list[-1])
        if f != -1:
          f.write( f'No:{pinf[0]};Time:{pinf[1]};Pac-size:{pinf[2]};' +
                   f'MAC-src:{pinf[3]};MAC-dest:{pinf[4]};Type:{pinf[5]};' + 
                   f'IP-src:{pinf[6]};IP-dest:{pinf[7]};Port-src:{pinf[8]};' + 
                   f'Port-dest:{pinf[9]};Len-data:{pinf[10]};!\n' )
      # Если это TCP-протокол  
      if proto == 6:
        pinf[5] = 'TCP'
        pinf[8], pinf[9], pinf[11], \
        pinf[12], flags, data_tcp = get_tcp_segment(data_ipv4)
        pinf[10] = len(data_tcp)
        pinf[13] = (flags & 16) >> 4
        pinf[14] = (flags & 8) >> 3
        pinf[15] = (flags & 4) >> 2
        pinf[16] = (flags & 2) >> 1
        pinf[17] = flags & 1
        Packet_list.append(PacketInf( pinf[0], pinf[1], pinf[2], pinf[3]
                                    , pinf[4], pinf[5], pinf[6], pinf[7]
                                    , pinf[8], pinf[9], pinf[10], pinf[11]
                                    , pinf[12], pinf[13], pinf[14], pinf[15]
                                    , pinf[16], pinf[17] ))
        print_packet_inf(Packet_list[-1])
        # print('#############################')
        # print(pinf[10], '---', len(format_data(data_tcp)))
        if f != -1:
          f.write( f'No:{pinf[0]};Time:{pinf[1]};Pac-size:{pinf[2]};' +
                   f'MAC-src:{pinf[3]};MAC-dest:{pinf[4]};Type:{pinf[5]};' + 
                   f'IP-src:{pinf[6]};IP-dest:{pinf[7]};Port-src:{pinf[8]};' + 
                   f'Port-dest:{pinf[9]};Len-data:{pinf[10]};Seq:{pinf[11]};' +
                   f'Ack:{pinf[12]};Fl-ack:{pinf[13]};Fl-psh:{pinf[14]};' +
                   f'Fl-rst:{pinf[15]};Fl-syn:{pinf[16]};Fl-fin:{pinf[17]};!\n' )
      if keyboard.is_pressed('space'):
        s_listen.close()
        print('Завершение программы...')
        break


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
                                  , a[6], a[7], a[8], a[9], a[10], a[11]
                                  , a[12], a[13], a[14], a[15], a[16], a[17] ))
    elif a[5] == 'UDP':
      Packet_list.append(PacketInf( a[0], a[1], a[2], a[3], a[4], a[5]
                                  , a[6], a[7], a[8], a[9], a[10] ))
  except:
    print('Ошибка при считывании файла...')
    exit(0)


def print_packet_inf(obj):
  print( f'{line}Пакет No{obj.numPacket}{line}\n'
       , 'Время перехвата: '
       , time.strftime( '%m:%d:%Y %H:%M:%S'
                      , time.localtime(obj.timePacket) ) + '\n'
       , f'Протокол: {obj.protoType}\n'
       , f'MAC-адрес отправителя: {obj.mac_src}\n'
       , f'MAC-адрес получателя: {obj.mac_dest}\n'
       , f'Порт отправителя: {obj.port_src} ---'
       , f'Порт получателя: {obj.port_dest}\n'
       , f'IP-адрес отправителя: {obj.ip_src} ---'
       , f'IP-адрес получателя: {obj.ip_dest}\n' )


# Получение общей информации о текущей
# попытке перехвата трафика
def get_common_data():
  IPList = set()
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
    IPList.add(p.ip_src)
    IPList.add(p.ip_dest)
  return list(IPList), numPacketsPerSec


# Вывод пар (число, IP-адрес) для
# предоставления выбора IP-адреса
# пользователю
def print_IP_list(IPList, fl=False):
  num = 0
  cnt = 1
  if fl:
    print ('[' + str(num), '---', 'None', end='] ')
    cnt += 1
    num += 1
  for el in IPList:
    if cnt > 3:
      cnt = 0
      print ('[' + str(num), '---', el, end=']\n')
    else:
      print ('[' + str(num), '---', el, end='] ')
    cnt += 1
    num += 1


# Вывод пакетов, связанных с выбранным IP-адресом 
def print_adjacent_packets(adjcPacketLIst):
  cnt = 0
  for p in adjcPacketLIst:
    t = time.strftime('%H:%M:%S', time.localtime(p.timePacket))
    if cnt % 2 == 1:
      print( f'Номер пакета: {p.numPacket};', f' Время: {t};'
           , f' Размер: {p.packetSize};', f' MAC-адрес отправителя: {p.mac_src};'
           , f' MAC-адрес получателя: {p.mac_dest};'
           , f' IP-адрес отправителя: {p.ip_src};', f' IP-адрес получателя: {p.ip_dest};'
           , f' Протокол: {p.protoType};', f' Порт отправителя: {p.port_src};'
           , f' Порт получателя: {p.port_dest};', f' Количество байт: {p.len_data};' )
    else:
      print( Back.CYAN + Fore.BLACK + f' Номер пакета: {p.numPacket};' + f' Время: {t};' +
             f' Размер: {p.packetSize};' + f' MAC-адрес отправителя: {p.mac_src};' +
             f' MAC-адрес получателя: {p.mac_dest};' +
             f' IP-адрес отправителя: {p.ip_src};' + f' IP-адрес получателя: {p.ip_dest};' +
             f' Протокол: {p.protoType};' + f' Порт отправителя: {p.port_src};' +
             f' Порт получателя: {p.port_dest};' + f' Количество байт: {p.len_data};' )
    cnt += 1



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
        print('yes')
        if Packet_list[k].ip_src == exploreIP:
          cntOutput += 1
        if Packet_list[k].ip_dest == exploreIP:
          cntInput += 1
    curTime += 1
  diff_list.append(cntOutput - cntInput)
  return diff_list


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
  adjcIPList = set()
  for p in Packet_list:
    if p.ip_src == exploreIP:
      adjcPacketList.append(p)
      adjcIPList.add(p.ip_dest)
    if p.ip_dest == exploreIP:
      adjcPacketList.append(p)
      adjcIPList.add(p.ip_src)
  return adjcPacketList, list(adjcIPList)


def get_pos_by_IP(curIP):
  for i in range(len(Object_list)):
    if Object_list[i].ip == curIP:
      return i
  return -1


# Получение меток и "шага" для оси абсцисс
def get_x_labels(total_time):
  global x_axisLabels
  step = 1
  if total_time > 600:
    step = 30
  elif total_time > 300:
    step = 10
  elif total_time > 50:
    step = 5
  if x_axisLabels == []:
    for i in range(0, len(Labels_list), step):
      x_axisLabels.append(Labels_list[i])
  return step

def get_2nd_IP_for_plot(k):
  print('Изобразить на графике еще один объект. Выберите ' + \
            'IP-адрес для добавления (нажмите цифру)')
  print_IP_list(Object_list[k].adjcIPList, True)
  scnd_IP = 'None'
  try:
    pos = int(input())
  except:
    print('Некорректный ввод!')
    return -1
  else:
    if pos < 0 or pos > len(Object_list[k].adjcIPList):
      print('Некорректный ввод!')
      return -1
    if pos != 0:
      scnd_IP = Object_list[k].adjcIPList[pos - 1]
  return scnd_IP

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
        Object_list[k].in_out_rel_data = get_in_out_rel(curIP, strt, fin)
      x = [i for i in range(0, len(Object_list[k].in_out_rel_data))]
      x_labels = [i for i in range(0, len(x), step)]
      scnd_IP = get_2nd_IP_for_plot(k)
      if scnd_IP == -1:
        continue
      if scnd_IP != 'None':
        pos = get_pos_by_IP(scnd_IP)
        if Object_list[pos].in_out_rel_data == None:
          Object_list[pos].in_out_rel_data = get_in_out_rel(scnd_IP, strt, fin)
      fig = plt.figure(figsize=(16, 6), constrained_layout=True)
      f = fig.add_subplot()
      f.grid()
      f.set_title('Отношение объема входящего к объему исходящего трафиков' + \
                  r' ($r_{in/out} = \frac{V_{in}}{V_{out}}$)', fontsize=15 )
      f.set_xlabel('Общее время перехвата трафика', fontsize=15)
      f.set_ylabel(r'$r_{in/out} = \frac{V_{in}}{V_{out}}$', fontsize=15)
      plt.plot(x, Object_list[k].in_out_rel_data, label=curIP)
      if scnd_IP != 'None':
        plt.plot(x, Object_list[pos].in_out_rel_data, label=scnd_IP)
      plt.xticks(x_labels, x_axisLabels, rotation=30, fontsize=10)
      f.legend()
      plt.show()
    elif bl == '3':
      if Object_list[k].udp_tcp_rel_data == None:
        Object_list[k].udp_tcp_rel_data = get_udp_tcp_rel(curIP, strt, fin)
      x = [i for i in range(0, len(Object_list[k].udp_tcp_rel_data))]
      x_labels = [i for i in range(0, len(x), step)]
      scnd_IP = get_2nd_IP_for_plot(k)
      if scnd_IP == -1:
        continue
      if scnd_IP != 'None':
        pos = get_pos_by_IP(scnd_IP)
        if Object_list[pos].udp_tcp_rel_data == None:
          Object_list[pos].udp_tcp_rel_data = get_udp_tcp_rel(scnd_IP, strt, fin)
      fig = plt.figure(figsize=(16, 6), constrained_layout=True)
      f = fig.add_subplot()
      f.grid()
      f.set_title( 'Отношение объема входящего UDP-трафика к объему ' +  
                   'входящего TCP-трафика' + r' ($r_{in} = \frac{V_{udp}}{V_{tcp}}$)'
                 , fontsize=15 )
      f.set_xlabel('Общее время перехвата трафика', fontsize=15)
      f.set_ylabel(r'$r_{in} = \frac{V_{udp}}{V_{tcp}}$', fontsize=15)
      plt.plot(x, Object_list[k].udp_tcp_rel_data, label=curIP)
      if scnd_IP != 'None':
        plt.plot(x, Object_list[pos].udp_tcp_rel_data, label=scnd_IP)
      plt.xticks(x_labels, x_axisLabels, rotation=30, fontsize=10)
      f.legend()
      plt.show()
    elif bl == '4':
      if Object_list[k].ack_flags_diff_data == None:
        # data = get_ack_flags_diff(curIP, strt, fin)
        Object_list[k].ack_flags_diff_data = get_ack_flags_diff(curIP, strt, fin)
      x = [i for i in range(0, len(Object_list[k].ack_flags_diff_data))]
      x_labels = [i for i in range(0, len(x), step)]
      scnd_IP = get_2nd_IP_for_plot(k)
      if scnd_IP == -1:
        continue
      if scnd_IP != 'None':
        pos = get_pos_by_IP(scnd_IP)
        if Object_list[pos].ack_flags_diff_data == None:
          Object_list[pos].ack_flags_diff_data = get_ack_flags_diff(scnd_IP, strt, fin)
      fig = plt.figure(figsize=(16, 6), constrained_layout=True)
      f = fig.add_subplot()
      f.grid()
      f.set_title('Разность числа исходящих и числа входящих ACK-флагов' + \
                  r' ($r_{ack} = V_{A_{out}} - V_{A_{in}}$)', fontsize=15)
      f.set_xlabel('Общее время перехвата трафика', fontsize=15)
      f.set_ylabel(r'$r_{ack} = V_{A_{out}} - V_{A_{in}}$', fontsize=15)
      plt.plot(x, Object_list[k].ack_flags_diff_data, label=curIP)
      if scnd_IP != 'None':
        plt.plot(x, Object_list[pos].ack_flags_diff_data, label=scnd_IP)
      plt.xticks(x_labels, x_axisLabels, rotation=30, fontsize=10)
      f.legend()
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
      scnd_IP = get_2nd_IP_for_plot(k)
      if scnd_IP == -1:
        continue
      if scnd_IP != 'None':
        pos = get_pos_by_IP(scnd_IP)
        if Object_list[pos].syn_flags_freq_data == None:
          data = get_syn_flags_freq(scnd_IP, strt, fin)
          Object_list[pos].syn_flags_freq_data = data
        if Object_list[pos].psh_flags_freq_data == None:
          data = get_psh_flags_freq(scnd_IP, strt, fin)
          Object_list[pos].psh_flags_freq_data = data
      fig = plt.figure(figsize=(16, 6), constrained_layout=True)
      gs = gridspec.GridSpec(ncols=1, nrows=2, figure=fig)
      fig_1 = fig.add_subplot(gs[0, 0])
      fig_1.grid()
      fig_1.set_title('Частота флагов SYN' + \
                       r' ($r_{syn} = \frac{V_{S_{in}}}{V_{tcp}}$)', fontsize=15)
      fig_1.set_xlabel('Общее время перехвата трафика', fontsize=15)
      fig_1.set_ylabel(r'$r_{syn} = \frac{V_{S_{in}}}{V_{tcp}}$', fontsize=15)
      plt.plot(x, Object_list[k].syn_flags_freq_data, 'b', label=curIP)
      if scnd_IP != 'None':
        plt.plot(x, Object_list[pos].syn_flags_freq_data, 'r', label=scnd_IP)
      plt.xticks(x_labels, x_axisLabels, rotation=30, fontsize=8)
      fig_1.legend()
      fig_2 = fig.add_subplot(gs[1, 0])
      fig_2.grid()
      plt.plot(x, Object_list[k].psh_flags_freq_data, 'g', label=curIP)
      fig_2.set_title('Частота флагов PSH' + \
                      r' ($r_{psh} = \frac{V_{P_{in}}}{V_{tcp}}$)', fontsize=15)
      fig_2.set_xlabel('Общее время перехвата трафика', fontsize=15)
      fig_2.set_ylabel(r'$r_{psh} = \frac{V_{P_{in}}}{V_{tcp}}$', fontsize=15)
      if scnd_IP != 'None':
        plt.plot(x, Object_list[pos].psh_flags_freq_data, 'y', label=scnd_IP)
      plt.xticks(x_labels, x_axisLabels, rotation=30, fontsize=8)
      fig_2.legend()
      plt.show()
    elif bl == '6':
      break


def choose_mode():
  while True:
    print('1. Перехват трафика и запись данных в файл')
    print('2. Перехват трафика для анализа данных')
    print('3. Считывание с файла данных для анализа трафика')
    print('4. Анализ трафика')
    print('5. Выход')
    bl = input()
    if bl == '1':
      Packet_list.clear()
      print('Введите название файла (например: data.log)')
      FileName = input()
      try:
        f = open(FileName, 'a')
      except:
        print('\nНекорректное название файла!\n')
        continue
      try:
        s_listen = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
      except PermissionError:
        print('\nНедостаточно прав!')
        print('Запустите программу от имени администратора!')
        return
      else:
        start_to_listen(s_listen, f)
      f.close()
      print(f'Данные собраны. Перехвачено: {len(Packet_list)} пакетов(-а)')
    elif bl == '2':
      Packet_list.clear()
      try:
        s_listen = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
      except PermissionError:
        print('\nНедостаточно прав!')
        print('Запустите программу от имени администратора!')
        return
      else:
        start_to_listen(s_listen)
      print(f'Данные собраны. Перехвачено: {len(Packet_list)} пакетов(-а)')
    elif bl == '3':
      Packet_list.clear()
      print('Введите название файла (например: data.log)')
      FileName = input()
      if not Packet_list:
        try:
          f = open(FileName, 'r')
        except:
          print('\nНекорректное название файла!\n')
          continue
        while True:
          inf = f.readline()
          if not inf:
            break
          read_from_file(inf)
        f.close()
      print(f'Данные собраны. Перехвачено: {len(Packet_list)} пакетов(-а)')
    elif bl == '4':
      if Packet_list == []:
        print('\nНет данных! Сначала необходимо получить данные!\n')
        continue
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
        print('\nНекорректный ввод!\n')
        continue
      else:
        if 0 <= k < len(IPList):
          choose_options(k, strt, fin, step)
        else:
          print(f'Введите число в пределах 0 - {len(IPList) - 1}')
    elif bl == '5':
      return


if __name__ == '__main__':
  print('\nЗапуск программы....\n')
  print('Выберите сетевой интерфейс, нажав соответствующую цифру:')
  print(socket.if_nameindex())
  interface = int(input())
  os.system(f'ip link set {socket.if_indextoname(interface)} promisc on')
  choose_mode()

