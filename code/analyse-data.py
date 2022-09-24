from cmath import exp
import matplotlib.pyplot as plt
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
    self.rel_with_other_ip_data = None
    self.ack_flags_diff_data = None
    self.udp_tcp_rel_data = None
    self.syn_flags_freq_data = None
    self.psh_flags_freq_data = None


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

#TODO переделать поиск веремени...strt = packet_list[0].timePacket...
def get_common_data():
  IPList = []
  timePacketList = []
  fl = False
  strt = 0.0
  fin = 0.0
  curTime = 0.0
  cntPacket = 0
  for pac in Packet_list:
    if not fl:
      strt = pac.timePacket
      curTime = strt + 1
      fl = True
    fin = pac.timePacket
    if pac.timePacket > curTime:
      timePacketList.append(cntPacket)
      cntPacket = 0
      curTime += 1
    cntPacket += 1
    CurIP = pac.ip_src
    if CurIP not in IPList:
      IPList.append(CurIP)
  return IPList, strt, fin, timePacketList


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
        print('output=', p.fl_ack)
        cntOutput += 1
      if p.ip_dest == exploreIP:
        print('input=', p.fl_ack)
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
  adjcIPList = []
  for p in Packet_list:
    if p.ip_src == exploreIP:
      adjcIPList.append(p)
    if p.op_dest == exploreIP:
      adjcIPList.append(p)
  return adjcIPList

def choose_options(k, strt):
  curIP = Object_list[k].ip

  while True:
    print(f"""Выберите опцию:
    1. Вывести весь трафик, связанный с {curIP}
    2. Построить график отношения входящего и исходящего трафиков
    3. Построить график отношения объема входящего UDP-трафика и объёма входящего TCP-трафика
    4. Построить график разности числа исходящих ACK-флагов и числа входящих в единицу времени
    5. Построить график частоты SYN и PSH флагов во входящих пакетах
    6. Вернуться к выбору IP-адреса """)
    bl = input()
    if bl == '1':
      print('1')
    elif bl == '2':
      if Object_list[k].in_out_rel_data == None:
        data = get_in_out_rel(curIP, strt)
        Object_list[k].in_out_rel_data = data
      x = [i for i in range(0, len(Object_list[k].in_out_rel_data))]
      plt.plot(x, Object_list[k].in_out_rel_data)
      plt.show()
    elif bl == '3':
      print('3')
    elif bl == '4':
      print('4')
    elif bl == '5':
      print('5')
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
      IPList, strt, fin, timePacketList = get_common_data()
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

    for k in range(0, len(IPList)):
      Object_list.append(ExploreObject(IPList[k]))
    print(f'Выберите цифру (0 - {len(IPList)}) для просмотра IP-адреса:')
    k = input()

    try:
      k = int(k)
    except:
      print('Некорректный ввод!')
      break
    else:
      if 0 <= k <= len(IPList):
        choose_options(k, strt)
      else:
        print(f'Введите число в пределах {0 - len(IPList)}')

    
    # d = get_psh_flags_freq(Object_list[0].ip, strt)
    # x = [i for i in range(0, len(d))]
    # # print(Object_list[0].psh_flags_freq_data)
    # # Object_list[0].psh_flags_freq_data = d
    # # print(Object_list[0].psh_flags_freq_data)
    # # print(d)
    # plt.plot(x, d)
    # plt.show()