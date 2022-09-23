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
    self.rel_with_other_ip = None
  
  def set_in_out_rel(self, data):
    self.in_out_rel_data = data


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
  for packet in Packet_list:
    if packet.ip_src == exploreIP:
      cntInput += 1
    if packet.ip_dest == exploreIP:
      cntOutput += 1
    if packet.timePacket > curTime:
        curTime += 1
        if cntOutput != 0:
          rel_list.append(cntInput / cntOutput)
        else:
          rel_list.append(0.0)
        cntInput = 0
        cntOutput = 0
  return rel_list


def get_adjacent_packets(exploreIP):
  adjcIPList = []
  for p in Packet_list:
    if p.ip_src == exploreIP:
      adjcIPList.append(p)
    if p.op_dest == exploreIP:
      adjcIPList.append(p)
  return adjcIPList


if __name__ == '__main__':
  f = open(FileName, 'r')
  cnt = 0
  while True:
    cnt += 1
    inf = f.readline()
    if not inf:
      break
    read_from_file(inf)

  IPList, strt, fin, timePacketList = get_common_data()
  strt_time = time.gmtime(strt)
  fin_time = time.gmtime(fin)


  print('Общая информация:')
  print('Время первого перехваченного пакета: ', time.asctime(strt_time))
  print('Время последнего перехваченного пакета: ', time.asctime(fin_time))
  print('Количество пакетов: ', len(Packet_list))
  print('Общее время перехвата: ', round(fin - strt, 3))
  avgPacketVal = 0
  for el in timePacketList:
    avgPacketVal += el
  avgPacketVal /= len(timePacketList)
  print('Среднее количество пакетов секунду: ', round(avgPacketVal, 3))
  avgSizePacket = 0
  for p in Packet_list:
    avgSizePacket += p.packetSize
  avgSizePacket /= len(Packet_list)
  print('Средний размер пакетов: ', round(avgSizePacket, 3))
  
  for k in range(0, len(IPList)):
    Object_list.append(ExploreObject(IPList[k]))

  d = get_in_out_rel(Object_list[0].ip, strt)
  x = [i for i in range(0, len(d))]
  print(d)
  plt.plot(x, d)
  plt.show()