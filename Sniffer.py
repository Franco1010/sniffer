import sys
from SnifferConstants import *
from EPacket import *
from tkinter import *
from Scanner import scann
from fpdf import FPDF

def ethernetWindowRow2Cols(pdf, root: Toplevel, l: str, r: str, **args):
    frame = Frame(master=root, height=1, width=1)
    label = Label(master=frame, text=l, font=LABEL_FONT, width=1, height=ROW_HEIGHT)
    text = Text(master=frame, font=TEXT_FONT, width=1, height=ROW_HEIGHT)
    text.configure(**args)
    text.insert(INSERT, r)
    label.pack(fill=X, side=LEFT, expand=TRUE)
    text.pack(fill=X, side=RIGHT, expand=TRUE)
    frame.pack(fill=X, side=TOP)
    txt = (str(l) + ": " + str(r)) if l else (str(r))
    pdf.set_font('DejaVu', '', 14)
    pdf.multi_cell(200, 5, txt, align='C')
    pdf.ln(2)

def ethernetWindow(root: Tk, e_packet: EPacket):
    pdf = FPDF()
    # pdf.set_font("Arial", size = 10)
    pdf.add_font('DejaVu', '', 'DejaVuSansCondensed.ttf', uni=True)
    pdf.set_font('DejaVu', '', 14)
    cur_window = Toplevel(root)
    cur_window.geometry("600x400")
    cur_window.title("Analizar un paquete desde PC")

    # ScrollBar to window
    canvas = Canvas(cur_window)
    scroll_y = Scrollbar(cur_window, orient="vertical", command=canvas.yview)
    frame = Frame(canvas)
    frame.bind('<Enter>', lambda e : canvas.bind_all('<MouseWheel>', lambda x : canvas.yview_scroll(-x.delta, UNITS)))
    frame.bind('<Leave>', lambda e : canvas.unbind_all('<MouseWheel'))

    # Complete packet to display at top
    top_text = Text(master=frame, height=10, width=1, font=TEXT_FONT)
    top_text.tag_configure("tag_name", justify='center')
    top_text.insert("1.0", e_packet.hexData())
    top_text.tag_add("tag_name", "1.0", "end")
    top_text.pack(fill=X, side=TOP)
    pdf.add_page()
    pdf.multi_cell(200, 5, e_packet.hexData(), align='C')

    e_frame = e_packet.getField(*EPacket.ETHERNET_FRAME)
    Label(master=frame, text="Cabecera Ethernet", font=TITLE_FONT, width=1, height=ROW_HEIGHT).pack(fill=X, side=TOP)
    pdf.set_font('DejaVu', '', 16)
    pdf.ln(5)
    pdf.multi_cell(200, 5, "Cabecera Ethernet", align='C')
    pdf.ln(5)
    ethernetWindowRow2Cols(pdf, frame, 'MAC destino', hexToMAC(e_frame.getField(*EFrame.DESTINATION_ADDRESS)))
    ethernetWindowRow2Cols(pdf, frame, 'MAC origen', hexToMAC(e_frame.getField(*EFrame.SOURCE_ADDRESS)))
    ethernetWindowRow2Cols(pdf, frame, 'Tipo de servicio', SERVICES.get(e_frame.getField(*EFrame.TYPE), 'Undefined'))

    # IPv4
    ip_dp = e_packet.getField(*EPacket.IP_DATA_PACKET)
    Label(master=frame, text="IPv4", font=TITLE_FONT, width=1, height=ROW_HEIGHT).pack(fill=X, side=TOP)
    pdf.set_font('DejaVu', '', 16)
    pdf.ln(5)
    pdf.multi_cell(200, 5, "IPv4", align='C')
    pdf.ln(5)
    ethernetWindowRow2Cols(pdf, frame, 'Version', decimal(ip_dp.getField(*IPDataPacket.VERSION)))
    ethernetWindowRow2Cols(pdf, frame, 'Longitud (bytes)', decimal(int(ip_dp.getField(*IPDataPacket.VERSION)) * int(ip_dp.getField(*IPDataPacket.IHL))))

    # TOS - Type of service
    tos = ip_dp.getField(*IPDataPacket.TOS)
    ethernetWindowRow2Cols(pdf, frame, 'TOS', hexadecimal(tos.hexData()))
    ethernetWindowRow2Cols(pdf, frame, '', 
        'Precedence: ' + TOS_PRECEDENCE.get(tos.getField(*TOS.PRECEDENCE), 'Undefined') + 
        '\nType: ' + TOS_TYPE.get(tos.getField(*TOS.TYPE_OF_SERVICE), 'Undefined') +
        '\nMBZ: ' + tos.getField(*TOS.MBZ),
        fg='green', height=3)

    ethernetWindowRow2Cols(pdf, frame, 'Longitud total del paquete', hexadecimal(ip_dp.getField(*IPDataPacket.TOTAL_LENGTH)))
    ethernetWindowRow2Cols(pdf, frame, '', str(int(ip_dp.getField(*IPDataPacket.TOTAL_LENGTH), HEX_SCALE)) + ' bytes',fg='green')
    ethernetWindowRow2Cols(pdf, frame, 'Identificacion', hexadecimal(ip_dp.getField(*IPDataPacket.IDENTIFICATION)))
    ethernetWindowRow2Cols(pdf, frame, 'Banderas', binary(ip_dp.getField(*IPDataPacket.FLAGS)))
    ethernetWindowRow2Cols(pdf, frame, '',
        '0: Reservado, siempre debe ser 0' +
        '\nDF: ' + ('Permite fragmentar' if ip_dp.getField(*IPDataPacket.FLAGS)[1] == '0' else 'No Permite fragmentar') + 
        '\nMF: ' + ('No es ultimo ' if ip_dp.getField(*IPDataPacket.FLAGS)[2] == '1' else 'Es el ultimo ') + 'fragmento del datagrama',
        fg='green', height=3)
    ethernetWindowRow2Cols(pdf, frame, 'Desplazamiento de fragmentacion', binary(ip_dp.getField(*IPDataPacket.OFFSET)))
    ethernetWindowRow2Cols(pdf, frame, 'Tiempo de vida', hexadecimal(ip_dp.getField(*IPDataPacket.TTL)))
    ethernetWindowRow2Cols(pdf, frame, '', str(int(ip_dp.getField(*IPDataPacket.TTL), HEX_SCALE)) + ' segundos',fg='green')
    ethernetWindowRow2Cols(pdf, frame, 'Protocolo', hexadecimal(ip_dp.getField(*IPDataPacket.PROTOCOL)))
    ethernetWindowRow2Cols(pdf, frame, '', IP_PROTOCOL.get(ip_dp.getField(*IPDataPacket.PROTOCOL), 'Undefined'),fg='green')
    ethernetWindowRow2Cols(pdf, frame, 'Checksum', hexadecimal(ip_dp.getField(*IPDataPacket.CHECKSUM)))
    checksum_correct = True if ip_dp.verifyChecksum() == "0xffff" else False
    ethernetWindowRow2Cols(pdf, frame, '', 'Checksum result: ' + ('OK' if checksum_correct else 'INCORRECT'),fg='green' if checksum_correct else 'red')
    ethernetWindowRow2Cols(pdf, frame, 'IP Origen', hexToIP(ip_dp.getField(*IPDataPacket.SOURCE_ADDRESS)))
    ethernetWindowRow2Cols(pdf, frame, 'IP Destino', hexToIP(ip_dp.getField(*IPDataPacket.DESTINATION_ADDRESSS)))

    # TCP
    Label(master=frame, text="TCP", font=TITLE_FONT, width=1, height=ROW_HEIGHT).pack(fill=X, side=TOP)
    pdf.set_font('DejaVu', '', 16)
    pdf.ln(5)
    pdf.multi_cell(200, 5, "TCP", align='C')
    pdf.ln(5)
    tcp = e_packet.getField(*EPacket.TCP)
    ethernetWindowRow2Cols(pdf, frame, 'Direccion puerto origen', decimal(int(tcp.getField(*TCP.SOURCE_PORT), HEX_SCALE)))
    ethernetWindowRow2Cols(pdf, frame, 'Direccion puerto destino', decimal(int(tcp.getField(*TCP.DESTINATION_PORT), HEX_SCALE)))
    ethernetWindowRow2Cols(pdf, frame, 'Numero de secuencia', hexadecimal(tcp.getField(*TCP.SEQUENCE_NUMBER)))
    ethernetWindowRow2Cols(pdf, frame, 'Numero de confirmacion', hexadecimal(tcp.getField(*TCP.ACK)))
    ethernetWindowRow2Cols(pdf, frame, 'Longitud de cabecera TCP', hexadecimal(tcp.getField(*TCP.HEADER_LENGTH)))
    ethernetWindowRow2Cols(pdf, frame, '', str(int(tcp.getField(*TCP.HEADER_LENGTH), BIN_SCALE) * int(ip_dp.getField(*IPDataPacket.VERSION))) + ' bytes',fg='green')
    ethernetWindowRow2Cols(pdf, frame, 'Reservado', binary(tcp.getField(*TCP.RESERVED)))
    ethernetWindowRow2Cols(pdf, frame, 'Flags', binary(tcp.getField(*TCP.FLAGS)))
    tcp_flags = tcp.getField(*TCP.FLAGS)
    ethernetWindowRow2Cols(pdf, frame, 'Flags', 
        'Nonce: ' + tcp_flags[0] + 
        '\nCongestion window reduced: ' + tcp_flags[1] + 
        '\nECN-Echo: ' + tcp_flags[2] + 
        '\nUrgent: ' + tcp_flags[3] + 
        '\nACK: ' + tcp_flags[4] + 
        '\nPush: ' + tcp_flags[5] + 
        '\nReset: ' + tcp_flags[6] + 
        '\nSyn: ' + tcp_flags[7] + 
        '\nFin: ' + tcp_flags[8],
        fg='green', height=9)
    ethernetWindowRow2Cols(pdf, frame, 'Tamano de la ventana', decimal(int(tcp.getField(*TCP.WINDOW_SZ), HEX_SCALE)))

    len = subHex(ip_dp.getField(*IPDataPacket.TOTAL_LENGTH), hex(int(ip_dp.getField(*IPDataPacket.VERSION)) * int(ip_dp.getField(*IPDataPacket.IHL))))
    foo = list(chunks((' '.join(tcp.hexData().splitlines())).replace(SPACE, NO_CHAR), 4))
    foo.remove(tcp.getField(*TCP.CHECKSUM))
    tcpwch = addListHex(' '.join(foo))
    tcpheaderlen = str(hex(int(tcp.getField(*TCP.HEADER_LENGTH), BIN_SCALE) * int(ip_dp.getField(*IPDataPacket.VERSION))))[2:]
    datalen = subHex(len, tcpheaderlen)
    inib = (EPacket.ETHERNET_FRAME[1] + EPacket.IP_DATA_PACKET[1] + EPacket.TCP[1])
    tcp_checksum = verifyChecksumTCP(
        addListHex(ip_dp.getField(*IPDataPacket.SOURCE_ADDRESS)),
        addListHex(ip_dp.getField(*IPDataPacket.DESTINATION_ADDRESSS)),
        len,
        tcpwch,
        addListHex(e_packet.getSubBytes(
        inib * 2,
        (inib + int(datalen, HEX_SCALE)) * 2
        ))
    )
    checksum_correct = tcp_checksum == tcp.getField(*TCP.CHECKSUM)
    ethernetWindowRow2Cols(pdf, frame, 'Checksum', hexadecimal(tcp.getField(*TCP.CHECKSUM)))
    ethernetWindowRow2Cols(pdf, frame, '', 'Checksum result: ' + ('OK' if checksum_correct else 'INCORRECT'),fg='green' if checksum_correct else 'red')
    ethernetWindowRow2Cols(pdf, frame, 'Puntero Urgente', hexadecimal(tcp.getField(*TCP.URGENT_POINT)))
    

    # Closing canvas with scrollbar
    canvas.create_window(0, 0, anchor=NW, window=frame, width=600)
    canvas.update_idletasks()
    canvas.configure(scrollregion=canvas.bbox(ALL), yscrollcommand=scroll_y.set)
    canvas.pack(fill=BOTH, expand=TRUE, side=LEFT)
    scroll_y.pack(fill=Y, side=RIGHT)
    pdf.output('Output.pdf')


def ethernetWindowLocal(root):
    lines = ""
    for line in sys.stdin:
        lines += line.strip() + SPACE
    lines = lines.replace(SPACE, NO_CHAR)

    # Creating EPacket from lines
    e_packet = EPacket(lines)
    ethernetWindow(root, e_packet)

def ethernetWindowWifi(root):
    # Creating EPacket from lines
    p = ' '.join(scann().splitlines())
    p = p.replace(SPACE, NO_CHAR)
    e_packet = EPacket(p)
    ethernetWindow(root, e_packet)

def main():
    

    root = Tk()
    root.geometry(ROOTWINDOWSIZE)
    root.title("Sniffer")
    root_title = Label(root, text = "Menu", font = TITLE_FONT)
    root_title.config(anchor=CENTER)
    root_title.pack(pady = 30)
    root_ethernet = Button(root,text ="Analizar un paquete desde PC",command = lambda : ethernetWindowLocal(root), font = LABEL_FONT)
    root_ethernet.config(anchor=CENTER)
    root_ethernet.pack(pady=30)
    root_ethernet.bind(root)
    root_wifi = Button(root,text ="Analizar un paquete desde Wifi",command = lambda : ethernetWindowWifi(root), font = LABEL_FONT)
    root_wifi.config(anchor=CENTER)
    root_wifi.pack()
    mainloop()

    # command = lambda: ethernetWindow(root, e_packet)

if __name__ == '__main__':
    main()