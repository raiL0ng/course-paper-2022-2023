import socket, threading, struct
import os, datetime, sys
import keyboard


def_port = 3389 # порт по умолчанию
white_list = {} # список верифицированных устройств
black_list = [] # список неизвестных устройств
Current_object = '' # Текущий неизвестный объект 
Cur_number = 1 # Счетчик всех перехваченных пакетов
Packet_cnt = 0 # Счетчик пакетов


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
  return src_port, dest_port, size, data[8:]


# Получение TCP-cегмента данных
def get_tcp_segment(data):
  src_port, dest_port, sequence, ack, some_block = struct.unpack('!HHLLH', data[:14])
  return src_port, dest_port, sequence, ack, data[(some_block >> 12) * 4:]


# Проверка порта по-умолчанию
def scan_port(src_ipv4, dest_ipv4, src_mac, src_port, dest_port):
  if dest_port == def_port:
    fl = False
    for key in white_list.keys():
      if key[1] == src_ipv4:
        fl = True
        break
    if not fl:
      for key in white_list.keys():
        if key[1] == dest_ipv4:
          tup = (src_ipv4, src_mac)    
          if tup not in black_list:
            black_list.append(tup)
            write_to_file((src_ipv4, src_mac, key[0], src_port, dest_port), False)


# Форматирование данных для корректного представления
def format_data(data):
  if isinstance(data, bytes):
    data = ''.join(r'\x{:02x}'.format(el) for el in data)
  return data


# Проверка данных TCP-сегмента
def scan_inf(r_data, src_ipv4, dest_ipv4, src_mac, dest_mac, dest_port, src_port):
  global Current_object
  global black_list
  global Packet_cnt
  data = format_data(r_data)
  flag = False
  for key in white_list.keys():
    if key[1] == src_ipv4:
      flag = True
      break
  if not flag:
    for key, value in white_list.items():
      if value[1] in data and key[1] == dest_ipv4:
        Current_object = (key[0], key[1], value[0])
        tup = (src_ipv4, src_mac)
        if tup not in black_list:
            black_list.append(tup)
            write_to_file(( src_ipv4, src_mac, Current_object[0]
                          , src_port, dest_port ), False)
  if Current_object:
    if Current_object[2] in data:
      for key in white_list.keys():
        if key[1] == src_ipv4:
          write_to_file(( dest_ipv4, dest_mac, Current_object[0]
                        , src_port, dest_port ), True)
          break
      Current_object = ''
    else:
      Packet_cnt += 1
      if Packet_cnt > 100:
        Packet_cnt = 0
        Current_object = ''  


# Перехват трафика и вывод информации в консоль
def start_to_listen(interface):
  global Current_object
  global Cur_number
  os.system(f'ip link set {socket.if_indextoname(interface)} promisc on')
  server = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
  # server.bind((socket.if_indextoname(interface), 0))
  while True:
    # Получение пакетов в виде набора hex-чисел
    raw_data, _ = server.recvfrom(65565)
    dest_mac, src_mac, protocol = get_ethernet_frame(raw_data)

    # Если это интернет-протокол четвертой версии    
    if protocol == 8:
      print(f'-------------------Пакет N{Cur_number}-----------------------')
      Cur_number += 1
      print('Ethernet кадр: ')
      print('MAC-адрес отправителя: ' + str(src_mac), 'MAC-адрес получателя: ' + str(dest_mac))
      ttl, proto, src_ipv4, dest_ipv4, data_ipv4 = get_ipv4_data(raw_data[14:])
      print('IPv4 заголовок:')
      print( 'TTL: ' + str(ttl)
           , 'Номер протокола: ' + str(proto)
           , 'IP-адрес отправителя: ' + str(src_ipv4)
           , 'IP-адрес получателя: ' + str(dest_ipv4))
      # Если это UDP-протокол  
      if proto == 17:
        src_port_udp, dest_port_udp, size, data_udp = get_udp_segment(data_ipv4)
        print('UDP заголовок:')
        print( 'Порт отправителя: ' + str(src_port_udp), 'Порт получателя: ' + 
               str(dest_port_udp), 'Размер: ' + str(size) )
        
        scan_port(src_ipv4, dest_ipv4, src_mac, src_port_udp, dest_port_udp)
      # Если это TCP-протокол  
      if proto == 6:
        src_port_tcp, dest_port_tcp, sequence, ack, data_tcp = get_tcp_segment(data_ipv4)
        print('TCP заголовок:')
        print( 'Порт отправителя: ' + str(src_port_tcp)
             , 'Порт получателя: ' + str(dest_port_tcp)
             , 'Порядковый номер: ' + str(sequence)
             , 'Номер подтверждения: ' + str(ack) )

        scan_port(src_ipv4, dest_ipv4, src_mac, src_port_tcp, dest_port_tcp)
        
        th_inf = threading.Thread(target=scan_inf, args=[ data_tcp
                                                        , src_ipv4
                                                        , dest_ipv4
                                                        , src_mac
                                                        , dest_mac
                                                        , dest_port_tcp
                                                        , src_port_tcp ])
        th_inf.start()
      if keyboard.is_pressed('space'):
        server.close()
        break


# Запись в файл
def write_to_file(tup, bl):
  try:
    time = str(datetime.datetime.now()).split('.')[0]
    with open('information.log', 'a+') as f:
      if bl:
        f.write('Было совершено подключение: ' + time)
        f.write( '\nIP адрес неизвестного клиента: ' + str(tup[0]) + 
                 ' MAC-адрес: ' + tup[1] )
        f.write( '\nПодключение к ПК ' + tup[2] + ' от порта ' + str(tup[3]) + 
                 ' к ' + str(tup[4]) + '\n' )
      else:
        f.write('Время попытки подключения: ' + time)
        f.write( '\nIP адрес неизвестного клиента: ' + str(tup[0]) + 
                 ' MAC-адрес: ' + tup[1] )
        f.write( '\nПодключение осуществлялось к ПК ' + tup[2] + ' от порта ' + 
                 str(tup[3]) + ' к ' + str(tup[4]) + '\n' )
      f.close()
  except:
    pass


# Форматирование строки в hex-код
def convert_string(string):
  s = ''
  for el in bytearray(string.encode('utf-8')):
    s += '\\' + str(hex(el))[1:]
  return s


# Получение списка верифицированных устройств
def get_white_list():
  f = open('white-list.log', 'r')
  while True:
    line = f.readline().replace('\n', '')
    if '#' in line:
      continue
    if not line:
      break
    pos = line.find('::')
    serv_name = line[:pos]
    serv_ip = line[pos + 2:]
    white_list[(serv_name, serv_ip)] = (convert_string(serv_name), convert_string(serv_ip))


# Осуществление запуска прошраммы
if __name__ == '__main__':
  print('\nЗапуск программы....\n')
  print('Хотите поменять RDP порт для анализа трафика? (по умолчанию 3389)')
  print('Если да, то нажмите 1, иначе - 0')
  bl = input()
  if bl == '1':
    print('Введите номер прослушиваемого RDP порта: ')
    def_port = int(input())
  
  print('Выберите сетевой интерфейс, нажав соответствующую цифру:')
  print(socket.if_nameindex())
  interface = int(input())
  try:
    get_white_list()
  except:
    print('Файл white-list.log не обнаружен')
    exit()
  else:
    start_to_listen(interface)
    