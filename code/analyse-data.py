import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import time


FileName = 'data.log'
Packet_list = []
Object_list = []

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


class ExploreObject:

  def __init__(self, ip):
    self.ip = ip
    self.in_out_rel_data = None
    self.ack_flags_diff_data = None
    self.udp_tcp_rel_data = None
    self.syn_flags_freq_data = None
    self.psh_flags_freq_data = None
    self.adjcIPList = None
    self.adjcPacketList = None


  # def set_in_out_rel(self, data):
  #   self.in_out_rel_data = data


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
  if a[5] == 'TCP':
    Packet_list.append(PacketInf( a[0], a[1], a[2], a[3], a[4], a[5]
                                , a[6], a[7], a[8], a[9], a[15], a[16]
                                , a[10], a[11], a[12], a[13], a[14] ))
  elif a[5] == 'UDP':
    Packet_list.append(PacketInf( a[0], a[1], a[2], a[3], a[4], a[5]
                                , a[6], a[7], a[8], a[9], a[10], a[11] ))

def get_common_data():
  IPList = []
  timePacketList = []
  curTime = Packet_list[0].timePacket + 1
  cntPacket = 0
  for pac in Packet_list:
    if pac.timePacket > curTime:
      timePacketList.append(cntPacket)
      cntPacket = 0
      curTime += 1
    cntPacket += 1
    CurIP = pac.ip_src
    if CurIP not in IPList:
      IPList.append(CurIP)
  return IPList, timePacketList


def get_in_out_rel(exploreIP, strt):
  cntInput = 0
  cntOutput = 0
  rel_list = []
  curTime = strt + 1
  for p in Packet_list:
    if p.timePacket > curTime:
        curTime += 1
        if cntOutput != 0:
          rel_list.append(cntInput / cntOutput)
        else:
          rel_list.append(0.0)
        cntInput = 0
        cntOutput = 0
    if p.ip_src == exploreIP:
      cntOutput += 1
    if p.ip_dest == exploreIP:
      cntInput += 1
  return rel_list


def get_ack_flags_diff(exploreIP, strt):
  cntInput = 0
  cntOutput = 0
  diff_list = []
  curTime = strt + 1
  for p in Packet_list:
    if p.timePacket > curTime:
        curTime += 1
        diff_list.append(cntOutput - cntInput)
        cntInput = 0
        cntOutput = 0
    if p.protoType == 'TCP' and p.fl_ack == '1':
      if p.ip_src == exploreIP:
        cntOutput += 1
      if p.ip_dest == exploreIP:
        cntInput += 1
  return diff_list


def get_udp_tcp_rel(exploreIP, strt):
  cntUDP = 0
  cntTCP = 0
  curTime = strt + 1
  rel_list = []
  for p in Packet_list:
    if p.timePacket > curTime:
        curTime += 1
        if cntTCP != 0:
          rel_list.append(cntUDP / cntTCP)
        else:
          rel_list.append(0.0)
        cntTCP = 0
        cntUDP = 0
    if p.ip_dest == exploreIP:
      if p.protoType == 'TCP':
        cntTCP += 1
      if p.protoType == 'UDP':
        cntUDP += 1
  return rel_list


def get_syn_flags_freq(exploreIP, strt):
  cntSynTCP = 0
  cntTCP = 0
  rel_list = []
  curTime = strt + 1
  for p in Packet_list:
    if p.timePacket > curTime:
        curTime += 1
        if cntTCP != 0:
          rel_list.append(cntSynTCP / cntTCP)
        else:
          rel_list.append(0.0)
        cntSynTCP = 0
        cntTCP = 0
    if p.ip_dest == exploreIP and p.protoType == 'TCP':
        if p.fl_syn == '1':
          cntSynTCP += 1
        else:
          cntTCP += 1
  return rel_list


def get_psh_flags_freq(exploreIP, strt):
  cntPshTCP = 0
  cntTCP = 0
  rel_list = []
  curTime = strt + 1
  for p in Packet_list:
    if p.timePacket > curTime:
        curTime += 1
        if cntTCP != 0:
          rel_list.append(cntPshTCP / cntTCP)
        else:
          rel_list.append(0.0)
        cntPshTCP = 0
        cntTCP = 0
    if p.ip_dest == exploreIP and p.protoType == 'TCP':
        if p.fl_psh == '1':
          cntPshTCP += 1
        else:
          cntTCP += 1
  return rel_list


def get_adjacent_packets(exploreIP):
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


def print_adjacent_packets(adjcPacketLIst):
  for p in adjcPacketLIst:
    t = time.asctime(time.gmtime(p.timePacket))
    print( f'Номер пакета: {p.numPacket};', f'Время: {t};'
         , f'Размер: {p.packetSize};', f'MAC-адрес отправителя: {p.mac_src};'
         , f'MAC-адрес получателя: {p.mac_dest};'
         , f'IP-адрес отправителя: {p.ip_src};', f'IP-адрес получателя: {p.ip_dest};'
         , f'Протокол: {p.protoType};', f'Порт отправителя: {p.port_src};'
         , f'Порт получателя: {p.port_dest};', f'Количество байт: {p.len_data};' )
  


def print_IP_list(IPList):
  num = 0
  cnt = 1
  for el in IPList:
    if cnt > 3:
      cnt = 0
      print ('[' + str(num), '---', el, ']')
    else:
      print ('[' + str(num), '---', el, end='] ')
    cnt += 1
    num += 1


def choose_options(k, strt):
  curIP = Object_list[k].ip
  while True:
    print(f"""Выберите опцию:
    1. Вывести весь трафик, связанный с {curIP}
    2. Построить график отношения входящего и исходящего трафиков
    3. Построить график отношения объема входящего UDP-трафика и объёма входящего TCP-трафика
    4. Построить график разности числа исходящих и числа входящих ACK-флагов в единицу времени
    5. Построить график частоты SYN и PSH флагов во входящих пакетах
    6. Вернуться к выбору IP-адреса """)
    bl = input()
    if bl == '1':
      if Object_list[k].adjcPacketList == None:
        Object_list[k].adjcPacketList, Object_list[k].adjcIPList = get_adjacent_packets(curIP)
      print_adjacent_packets(Object_list[k].adjcPacketList)
    elif bl == '2':
      if Object_list[k].in_out_rel_data == None:
        data = get_in_out_rel(curIP, strt)
        Object_list[k].in_out_rel_data = data
      x = [i for i in range(0, len(Object_list[k].in_out_rel_data))]
      _, ax = plt.subplots()
      ax.plot(x, Object_list[k].in_out_rel_data)
      ax.set_xlabel('Время (с)', fontsize=15)
      # ax.set_ylabel('Отношение входящего и исходящего трафиков', fontsize=15)
      plt.show()
    elif bl == '3':
      if Object_list[k].udp_tcp_rel_data == None:
        data = get_udp_tcp_rel(curIP, strt)
        Object_list[k].udp_tcp_rel_data = data
      x = [i for i in range(0, len(Object_list[k].udp_tcp_rel_data))]
      _, ax = plt.subplots()
      ax.plot(x, Object_list[k].udp_tcp_rel_data)
      ax.set_xlabel('Время (с)', fontsize=15)
      # ax.set_ylabel('Отношение объема входящего UDP-трафика и объема исходящего TCP-трафика', fontsize=15)
      plt.show()
    elif bl == '4':
      if Object_list[k].ack_flags_diff_data == None:
        data = get_ack_flags_diff(curIP, strt)
        Object_list[k].ack_flags_diff_data = data
      x = [i for i in range(0, len(Object_list[k].ack_flags_diff_data))]
      _, ax = plt.subplots()
      ax.plot(x, Object_list[k].ack_flags_diff_data)
      ax.set_xlabel('Время (с)', fontsize=15)
      plt.show()
    elif bl == '5':
      if Object_list[k].syn_flags_freq_data == None:
        data = get_syn_flags_freq(curIP, strt)
        Object_list[k].syn_flags_freq_data = data
      if Object_list[k].psh_flags_freq_data == None:
        data = get_psh_flags_freq(curIP, strt)
        Object_list[k].psh_flags_freq_data = data
      x = [i for i in range(0, len(Object_list[k].syn_flags_freq_data))]
      fig = plt.figure(figsize=(7, 3), constrained_layout=True)
      gs = gridspec.GridSpec(ncols=2, nrows=1, figure=fig)
      fig_1 = fig.add_subplot(gs[0, 0])
      plt.plot(x, Object_list[k].syn_flags_freq_data)
      fig_2 = fig.add_subplot(gs[0, 1])
      plt.plot(x, Object_list[k].psh_flags_freq_data)
      fig_1.set_xlabel('Время (с)', fontsize=15)
      fig_2.set_xlabel('Время (с)', fontsize=15)
      plt.show()
    elif bl == '6':
      break
    

if __name__ == '__main__':
  while True:
    if not Packet_list:
      f = open(FileName, 'r')
      while True:
        inf = f.readline()
        if not inf:
          break
        read_from_file(inf)
      f.close()
      IPList, timePacketList = get_common_data()
      strt = Packet_list[0].timePacket
      fin = Packet_list[-1].timePacket
      strt_time = time.gmtime(strt)
      fin_time = time.gmtime(fin)
      avgPacketVal = 0
      for el in timePacketList:
        avgPacketVal += el
      avgPacketVal /= len(timePacketList)
      avgSizePacket = 0
      for p in Packet_list:
        avgSizePacket += p.packetSize
      avgSizePacket /= len(Packet_list)

    print('Общая информация:')
    print('Время первого перехваченного пакета: ', time.asctime(strt_time))
    print('Время последнего перехваченного пакета: ', time.asctime(fin_time))
    print('Количество пакетов: ', len(Packet_list))
    print('Общее время перехвата: ', round(fin - strt, 3))
    print('Среднее количество пакетов секунду: ', round(avgPacketVal, 3))
    print('Средний размер пакетов: ', round(avgSizePacket, 3))
    print('Завершить просмотр (нажмите \"q\" для выхода)')

    for k in range(0, len(IPList)):
      Object_list.append(ExploreObject(IPList[k]))
    print_IP_list(IPList)
    print(f'Выберите цифру (0 - {len(IPList) - 1}) для просмотра IP-адреса:')
    k = input()
    if k == 'q':
      break
    try:
      k = int(k)
    except:
      print('Некорректный ввод!')
      break
    else:
      if 0 <= k < len(IPList):
        choose_options(k, strt)
      else:
        print(f'Введите число в пределах 0 - {len(IPList) - 1}')

    
    # d = get_psh_flags_freq(Object_list[0].ip, strt)
    # x = [i for i in range(0, len(d))]
    # # print(Object_list[0].psh_flags_freq_data)
    # # Object_list[0].psh_flags_freq_data = d
    # # print(Object_list[0].psh_flags_freq_data)
    # # print(d)
    # plt.plot(x, d)
    # plt.show()