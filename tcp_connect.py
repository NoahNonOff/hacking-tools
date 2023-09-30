#!/bin/python3

import sys
import socket

usage = "Usage: {} <url> <port>"

def main():
	if len(sys.argv) != 3:
		print (usage.format(sys.argv[0]))
		return
	url = sys.argv[1]
	port = int(sys.argv[2])
	ip = socket.gethostbyname(url)

	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.connect((ip, port))

		# ---------- do whatever you want ---------- #
		data = s.recv(1024)
		print (data)

		message = ""
		answer = str(message) + '\n'
		s.sendall(answer.encode('UTF-8'))
		# ------------------------------------------ #

		s.close()


if __name__=="__main__":
	main()