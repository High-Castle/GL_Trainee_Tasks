import sys, socket, time, re, threading as multi

ip, port, resource, part_timeout, recv_timeout, number_of_clients = sys.argv[1:]

port, part_timeout, recv_timeout, number_of_clients = int(port), \
    float(part_timeout), float(recv_timeout), int(number_of_clients)

parts = ["G", "ET", " "] + list(resource) + [" H" ,"TTP/1", 
		 ".1\r" "\nConnec" , "tion", " :  kEeP-", "alivE \r", 
		 "\n  ", "  \r\n"]

def request_partial(seq_num):    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock.connect((ip, port))
    
    try:
        for part in parts :
            sock.sendall(part)              
            time.sleep(part_timeout)
        
        sock.settimeout(recv_timeout)
        
        response_str, header_end = str(), int()        
        
        while True:
            received = sock.recv(1024)
            if not received: 
                raise Exception("Received header is not complete: %s" % received)
            
            response_str += received
            header_end = response_str.rfind("\r\n\r\n") 
            if header_end != -1: 
                header_end += len("\r\n\r\n")
                break
        
        response = response_str[:header_end].split("\r\n")
        
        if int(response[0].split()[1]) != 200:
            raise Exception("\"%s\"" % response[0])
        
        class parsing : pass
        parse = parsing()
        
        for header in response[1:]:
            if not header: break
            name_value = header.split(":")
            if "Content-Length".lower() in name_value[0].lower():
                parse.content_length = int(name_value[1])
        
        remaining_to_receive = parse.content_length - (len(response_str) - header_end)
        
        out_filename = "file_" + str(seq_num) + "_" + str(sock.getsockname()[1])
        
        with file(out_filename, "w+") as out:
            out.write(response_str[header_end:])
            while remaining_to_receive:
                received = sock.recv(1024)
                if not received: break
                out.write(received)
                remaining_to_receive -= len(received)
        
        if remaining_to_receive: 
            raise Exception("not all received")

    except Exception as e:
        print "Client " + str(sock.getsockname()[1]) + " : " + e.message    
    
    sock.close()

requestors = [multi.Thread(target = request_partial, args=(num,))
    for num in xrange(number_of_clients)]

for each in requestors:
    each.start()
	
for each in requestors:  
    each.join()
