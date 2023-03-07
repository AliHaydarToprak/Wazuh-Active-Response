#!/usr/bin/python3
# Copyright (C) 2015-2022, Wazuh Inc.
# All rights reserved.

import os
import sys
import json
import datetime

if os.name == 'nt':
	LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
else:
	LOG_FILE = "/var/ossec/logs/active-responses.log"

ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3

OS_SUCCESS = 0
OS_INVALID = -1

class message:
	def __init__(self):
		self.alert = ""
		self.command = 0

def write_debug_file(ar_name, msg):
	with open(LOG_FILE, mode="a") as log_file:
		log_file.write(str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')) + " " + ar_name + ": " + msg +"\n")

def setup_and_check_message(argv):

	# get alert from stdin
	input_str = ""
	for line in sys.stdin:
		input_str = line
		break
    
	write_debug_file(argv[0], input_str)

	try:
		data = json.loads(input_str)
	except ValueError:
		write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
		message.command = OS_INVALID
		return message

	message.alert = data

	command = data.get("command")

	if command == "add":
		message.command = ADD_COMMAND
	elif command == "delete":
		message.command = DELETE_COMMAND
	else:
		message.command = OS_INVALID
		write_debug_file(argv[0], 'Not valid command: ' + command)

	return message


def send_keys_and_check_message(argv, keys):

	# build and send message with keys
	keys_msg = json.dumps({"version": 1,"origin":{"name": argv[0],"module":"active-response"},"command":"check_keys","parameters":{"keys":keys}})

	write_debug_file(argv[0], keys_msg)

	print(keys_msg)
	sys.stdout.flush()

	# read the response of previous message
	input_str = ""
	while True:
		line = sys.stdin.readline()
		if line:
			input_str = line
			break

	# write_debug_file(argv[0], input_str)

	try:
		data = json.loads(input_str)
	except ValueError:
		write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
		return message

	action = data.get("command")

	if "continue" == action:
		ret = CONTINUE_COMMAND
	elif "abort" == action:
		ret = ABORT_COMMAND
	else:
		ret = OS_INVALID
		write_debug_file(argv[0], "Invalid value of 'command'")

	return ret

def main(argv):

	write_debug_file(argv[0], "Started")

	# validate json and get command
	msg = setup_and_check_message(argv)
	r = str(msg.command)
	write_debug_file(argv[0], r + " Ali")
	
	alert = msg.alert["parameters"]["alert"]
	name = str(alert["data"]["win"]["eventdata"]["originalFileName"])
	os.system("taskkill /f /im " + name)
	
	write_debug_file(argv[0], "Ended")

if __name__ == "__main__":
	main(sys.argv)