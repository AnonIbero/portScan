def requisitos(): 
    try:
        import nmap
        import os
        import sys
        scanmap()
    except ModuleNotFoundError as b:
        print(str(b)) 
        print("\nIntentado instalar requisitos...\n" )
        requisitos1()
    
            
            

def ayuda():
    ayuda = """

Parametros:

-u [UDP Scan]
-s [SYNC Scan]
-f [Fragmented Scan]
-all [Todos los parametros de escaneo]
-requisitos [Instalar requerimientos]

Ejemplo: TPC Scan = python3 portScan <ip> <port>
         UDP Scan = python3 portScan -u <ip> <port>


Ejemplo de rango de puertos: python3 PortScan -all portScan <ip> 0-100

"""
    if __name__ == "__main__":
        print(ayuda)

def logo():
    logo ="""
+------------------------------------------------------------+
|MMMMMMMMMMMMMMMMMMMMMMKdc,.      .,cdKMMMMMMMMMMMMMMMMMMMMMM|
|MMMMMMMMMMMMMMMMWOocccldk0KXNNNNXKOkdc:::oOWMMMMMMMMMMMMMMMM|
|MMMMMMMMMMMMMKo::d0WMWNMMMMXdWxkxXOKNXWMW0d:;lKMMMMMMMMMMMMM|
|MMMMMMMMMMXl;l0MMXWkOolXMMMNxWxOxOdOK;lxOKXMW0c,lXMMMMMMMMMM|
|MMMMMMMMK;;OMMK0koxxX0XMMMMMMMMMMMMMWWKKkOdkoMMWk';KMMMMMMMM|
|MMMMMMK;;KMNk:lk0XMMMMWNNNXXXXKXXXNNNWMMMMX0ok:kNMO,;KMMMMMM|
|MMMMMo'0MNkkkxNMMMWNNNWNNNWNWNNMWNNNNWNNNWMMMNxloOWMk.oMMMMM|
|MMMX'cWMXdOdXMMMNXXNWWNWMMNMMNNMMWMMNXWNNNNWMMM0OKx0MW;'XMMM|
|MMN.dMM0cckMMMWXWMMWXNNNNXNNlxc;0NXNNNXNMMMNXWMMMO:lKMMl.XMM|
|MW'dMM0OdKMMMNXMMMMNWMMMNNMWd0l kMNWMMMNNMMMMXNMMMKXOkMMl.WM|
|M:;MMWxkOMMMXNWWWWNXWMMMXWMMMKdWMMMXMMMWXNNWWWNNMMMkK0MMM,;M|
|O XMMx:oWMMNNMMMMWXWWNNXKNNNN:cNNNNXNNNWWKMMMMMNNMMMoOkMMK O|
|;cMMMkdOMMWXMMMMMNWMMMMNXMMMM00MMMMNNMMMMXNMMMMMXMMMOKkMMM;;|
|.OMMK:cNMMNNMMMMMXMMMMMNNMMMNOONWMMWNMMMMNXMMMMMNWMMNc:XMMx.|
| XMMMKxNMMNXWWWWWXNWWWNXOl;MX;,0W:l0XWWWWNXWWWWWXWMMNxOWMM0 |
| XMMk,MMMMNNMMMMMXMO;'.   lMMdlWMl  .';coXXMMMMMNWMMMW.xMM0 |
|.OMM: xMMMMXMMMMMNN.      lMM:.MM:       oNMMMMMXMMMWo :MMd.|
|::MNd 'kOMMNNMMMMNd       .NM. XX        ;WMMMMNWMMok. dXM,;|
|O XO'o.O KWMNNWWWW;        .X. k.        .NWWWNNMWO O,o.00 O|
|M:;Wl :K dl0MNNMMX     ;;,.;;'            KMMNWMkol.O'.kW':M|
|MW'okoc. ,0 kMWNNx    ;lol.;,.            dNNMMx O. ;xxkc'WM|
|MMN.oc.cl:N' ONWW:    o;,;,...            cWWNk ,Xdd:.oc.NMM|
|MMMN,:k;  ':. xcl;         :;:c.          ,lcd .:. .:O,'XMMM|
|MMMMMd'OXccc;'.do          .:l;dcll;:      dd',:lclNk.oMMMMM|
|MMMMMMX:,xc..,;::;          :,.c:o:',    .;::;,..lx';KMMMMMM|
|MMMMMMMMK;,kKl:odxdol.       .,.;co.  :lodxdo:oKx';KMMMMMMMM|
|MMMMMMMMMMXl,ccc,.  .        .lcdl,   ..  .,cc:'lXMMMMMMMMMM|
|MMMMMMMMMMMMMKo;:o0Nd        .ocl'    xMNOo;;oKMMMMMMMMMMMMM|
|MMMMMMMMMMMMMMMMW0o:'         c:.     .;:oOWMMMMMMMMMMMMMMMM|
|MMMMMMMMMMMMMMMMMMMMMM0o;.        .;o0WMMMMMMMMMMMMMMMMMMMMM|
+------------------------------------------------------------+
                    ANONYMOUS IBEROAMERICA"""
    if __name__ == "__main__":
        print(logo)

def scanmap():
    try:
        import nmap
        import os
        import sys
        try:
            argumento = sys.argv[1]
            argumento2 = sys.argv[2]
            os.system("clear")
            logo()
            if argumento == "-u":
                argumento3 = sys.argv[3]
                scanmap1(argumento2, argumento3)
            if argumento == "-s":
                argumento3 = sys.argv[3]
                scanmap2(argumento2, argumento3)
            if argumento == "-f":
                argumento3 = sys.argv[3]
                scanmap3(argumento2, argumento3)
            if argumento == "-all":
                argumento3 = sys.argv[3]
                scanmap4(argumento2, argumento3)
            if argumento == "-requisitos":
                requisitos1()
            else:

                nm = nmap.PortScanner()
                nms = nm.scan(f"{argumento}", f"{argumento2}")

                for host in nm.all_hosts():
                    print('\nHost : %s (%s)' % (host, nm[host].hostname()))
                    print('Estado: %s' % (nm[host].state()))

                    for protocolo in nm[argumento].all_protocols():
                        print('Protocolo: %s' % (protocolo)) 

                        lport = nm[host][protocolo].keys()
                        
                        for puerto in lport:
                            print("\nPuerto: {0} | Nombre: {1} | Estado: {2} | Version: {3}\n".format(puerto, nm[host][protocolo][puerto]['name'], nm[host][protocolo][puerto]['state'], nm[host][protocolo][puerto]['version']))
            

        except IndexError:
            ayuda()
                          
            
    except KeyboardInterrupt:
        print("")
        sys.exit()

def scanmap1(argumento2, argumento3):
    try:
        import nmap
        import os
        import sys
        try:
            os.system("clear")
            logo()
                
            nm = nmap.PortScanner()
            nms = nm.scan(f"{argumento2}", f"{argumento3}", arguments="-sU -sV")

            for host in nm.all_hosts():
                print('\nHost : %s (%s)' % (host, nm[host].hostname()))
                print('Estado: %s' % (nm[host].state()))

                for protocolo in nm[argumento2].all_protocols():
                    print('Protocolo: %s' % (protocolo)) 

                    lport = nm[host][protocolo].keys()
                     
                    for puerto in lport:
                        print("\nPuerto: {0} | Nombre: {1} | Estado: {2} | Version: {3}\n".format(puerto, nm[host][protocolo][puerto]['name'], nm[host][protocolo][puerto]['state'], nm[host][protocolo][puerto]['version']))
            

        except IndexError:
            ayuda()

            
    except KeyboardInterrupt:
        print("")
        sys.exit()

def scanmap2(argumento2, argumento3):
    try:
        import nmap
        import os
        import sys
        try:
            os.system("clear")
            logo()
                
            nm = nmap.PortScanner()
            nms = nm.scan(f"{argumento2}", f"{argumento3}", arguments="-sS -sV")

            for host in nm.all_hosts():
                print('\nHost : %s (%s)' % (host, nm[host].hostname()))
                print('Estado: %s' % (nm[host].state()))

                for protocolo in nm[argumento2].all_protocols():
                    print('Protocolo: %s' % (protocolo)) 

                    lport = nm[host][protocolo].keys()
                     
                    for puerto in lport:
                        print("\nPuerto: {0} | Nombre: {1} | Estado: {2} | Version: {3}\n".format(puerto, nm[host][protocolo][puerto]['name'], nm[host][protocolo][puerto]['state'], nm[host][protocolo][puerto]['version']))
            

        except IndexError:
            ayuda()

            
    except KeyboardInterrupt:
        print("")
        sys.exit()

def scanmap3(argumento2, argumento3):
    try:
        import nmap
        import os
        import sys
        try:
            os.system("clear")
            logo()
                
            nm = nmap.PortScanner()
            nms = nm.scan(f"{argumento2}", f"{argumento3}", arguments="-f --mtu 8")

            for host in nm.all_hosts():
                print('\nHost : %s (%s)' % (host, nm[host].hostname()))
                print('Estado: %s' % (nm[host].state()))

                for protocolo in nm[argumento2].all_protocols():
                    print('Protocolo: %s' % (protocolo)) 

                    lport = nm[host][protocolo].keys()
                     
                    for puerto in lport:
                        print("\nPuerto: {0} | Nombre: {1} | Estado: {2} | Version: {3}\n".format(puerto, nm[host][protocolo][puerto]['name'], nm[host][protocolo][puerto]['state'], nm[host][protocolo][puerto]['version']))
            

        except IndexError:
            ayuda()

            
    except KeyboardInterrupt:
        print("")
        sys.exit()

def scanmap4(argumento2, argumento3):
    try:
        import nmap
        import os
        import sys
        try:
            os.system("clear")
            logo()
                
            nm = nmap.PortScanner()
            nms = nm.scan(f"{argumento2}", f"{argumento3}", arguments="-sU -sS -f --mtu 8")

            for host in nm.all_hosts():
                print('\nHost : %s (%s)' % (host, nm[host].hostname()))
                print('Estado: %s' % (nm[host].state()))

                for protocolo in nm[argumento2].all_protocols():
                    print('Protocolo: %s' % (protocolo)) 

                    lport = nm[host][protocolo].keys()
                     
                    for puerto in lport:
                        print("\nPuerto: {0} | Nombre: {1} | Estado: {2} | Version: {3}\n".format(puerto, nm[host][protocolo][puerto]['name'], nm[host][protocolo][puerto]['state'], nm[host][protocolo][puerto]['version']))
            

        except IndexError:
            ayuda()

            
    except KeyboardInterrupt:
        print("")
        sys.exit()

def requisitos1():
    import os
    os.system("apt-get install python3-pip")
    os.system("pip3 install nmap")
    os.system("pip3 install python-nmap")

if __name__ == "__main__":
    requisitos()


    

