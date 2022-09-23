import socket, datetime, struct
import os, time
import keyboard


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
  return str(ttl), proto, ipv4_dec(src), ipv4_dec(dest), data[header_length:]


# Получение IP-адреса формата X.X.X.X
def ipv4_dec(ip_bytes):
  ip_str = ''
  for el in ip_bytes:
    ip_str += str(el) + '.'
  return ip_str[:-1]


# Получение UDP-сегмента данных
def get_udp_segment(data):
  src_port, dest_port, size = struct.unpack('!HH2xH', data[:8])
  return str(src_port), str(dest_port), str(size), data[8:]


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
def start_to_listen(s_listen):
  NumPacket = 1
  while True:
    # Получение пакетов в виде набора hex-чисел
    raw_data, _ = s_listen.recvfrom(65565)
    arr_data = [''] * 17
    arr_data[0], arr_data[1] = str(NumPacket), str(time.time())
    arr_data[2] = str(len(raw_data))
    # Если это интернет-протокол четвертой версии    
    arr_data[4], arr_data[3], protocol = get_ethernet_frame(raw_data)
    if protocol == 8:
      print(f'-------------------Пакет N{NumPacket}-----------------------')
      NumPacket += 1
      print('Ethernet кадр: ')
      print( 'MAC-адрес отправителя: ' + arr_data[3]
           , 'MAC-адрес получателя: ' + arr_data[4] )
      ttl, proto, arr_data[6], arr_data[7], data_ipv4 = get_ipv4_data(raw_data[14:])
      print('IPv4 заголовок:')
      print( 'TTL: ' + ttl
           , 'Номер протокола: ' + str(proto)
           , 'IP-адрес отправителя: ' + arr_data[6]
           , 'IP-адрес получателя: ' + arr_data[7])
      # Если это UDP-протокол  
      if proto == 17:
        arr_data[5] = 'UDP'
        arr_data[8], arr_data[9], length, data_udp = get_udp_segment(data_ipv4)
        print('UDP заголовок:')
        print( 'Порт отправителя: ' + arr_data[8], 'Порт получателя: ' + 
               arr_data[9], 'Длина: ' + length )
        arr_data[10], arr_data[11] = str(len(data_udp)), format_data(data_udp)
        write_to_file(arr_data)
      # Если это TCP-протокол  
      if proto == 6:
        arr_data[5] = 'TCP'
        arr_data[8], arr_data[9], arr_data[10], arr_data[11], flags, data_tcp = get_tcp_segment(data_ipv4)
        fl_urg = str((flags & 32) >> 5)
        fl_ack = str((flags & 16) >> 4)
        fl_psh = str((flags & 8) >> 3)
        fl_rst = str((flags & 4) >> 2)
        fl_syn = str((flags & 2) >> 1)
        fl_fin = str(flags & 1)
        print('TCP заголовок:')
        print( 'Порт отправителя: ' + arr_data[8]
             , 'Порт получателя: ' + arr_data[9]
             , 'Порядковый номер: ' + arr_data[10]
             , 'Номер подтверждения: ' + arr_data[11] )
        print('Флаги:')
        print( 'URG: ' + fl_urg, 'ACK: ' + fl_ack, 'PSH: ' + fl_psh
             , 'RST: ' + fl_rst, 'SYN: ' + fl_syn, 'FIN: ' + fl_fin )
        arr_data[12], arr_data[13], arr_data[14] = fl_ack, fl_psh, fl_syn
        arr_data[15], arr_data[16] = str(len(data_tcp)), format_data(data_tcp)
        write_to_file(arr_data)
      if keyboard.is_pressed('space'):
        s_listen.close()
        break


# Запись в файл
def write_to_file(a):
  try:
    with open('data.log', 'a') as f:
      if a[5] == 'TCP':
        f.write( 'No:' + a[0] + ';' + 'Time:' + a[1] + ';' +
                 'Pac-size:' + a[2] + ';' + 'MAC-src:' + a[3] + ';' + 
                 'MAC-dest:' + a[4] + ';' + 'Type:' + a[5] + ';' +
                 'IP-src:' + a[6] + ';' + 'IP-dest:' + a[7] + ';' +
                 'Port-src:' + a[8] + ';' + 'Port-dest:' + a[9] + ';' +
                 'Seq:' + a[10] + ';' + 'Ack:' + a[11] + ';' +
                 'Fl-ack:' + a[12] + ';' + 'Fl-psh:' + a[13] + ';' +
                 'Fl-syn:' + a[14] + ';' + 'Len-data:' + a[15] + ';' + 
                 'Data:' + a[16] + ';!\n') 
      else:
        f.write( 'No:' + a[0] + ';' + 'Time:' + a[1] + ';' +
                 'Pac-size:' + a[2] + ';' + 'MAC-src:' + a[3] + ';' + 
                 'MAC-dest:' + a[4] + ';' + 'Type:' + a[5] + ';' +
                 'IP-src:' + a[6] + ';' + 'IP-dest:' + a[7] + ';' +
                 'Port-src:' + a[8] + ';' + 'Port-dest:' + a[9] + ';' +
                 'Len-data:' + a[10] + ';' + 'Data:' + a[11] + ';!\n')
      f.close()
  except:
    print('Ошибка записи в файл...')
    pass


# Осуществление запуска прошраммы
if __name__ == '__main__':
  print('\nЗапуск программы....\n')

  print('Выберите сетевой интерфейс, нажав соответствующую цифру:')
  print(socket.if_nameindex())
  interface = int(input())
  os.system(f'ip link set {socket.if_indextoname(interface)} promisc on')
  s_listen = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
  start_to_listen(s_listen)
    