# WAZUH Active-Response : Blocking Unwanted Software Vendors on Windows using CDB Lists

## Scenario

Let's assume that an unwanted software vendor's process is created on our Windows device and we want them to be interrupted.

so lets follow the steps below

## Configuration on Agent

Remote commands may be specified in the centralized configuration, however, they are disabled by default due to security reasons.

When setting commands in a shared agent configuration, you must enable remote commands for Agent Modules.

This is enabled by adding the following line to the file "C:\Program Files (x86)\ossec-agent\local_internal_options.conf" in the agent:

	wazuh_command.remote_commands=1

### 1-) To install and Monitoring Sysmon Activities

1. Download Sysmon.

	https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

2. Create an XML configuration for Sysmon

	https://github.com/SwiftOnSecurity/sysmon-config

3. Install Sysmon

	Sysmon64.exe -accepteula -i sysconfig.xml

4. Monitor Sysmon Activities for Wazuh

	cd C:\Program Files (x86)\ossec-agent

We add the following lines to the ossec.conf file to sysmon events monitoring.

	<localfile>
		<location>Microsoft-Windows-Sysmon/Operational</location>
		<log_format>eventchannel</log_format>
	</localfile>

### 2-) Install Python3
Download the Python executable installer from the official Python website.

Run the Python installer once downloaded. Make sure to check the following boxes:

	Install launcher for all users

	Add Python 3.X to PATH (This places the interpreter in the execution path)

Once Python completes the installation process, open an administrator PowerShell terminal and use pip to install PyInstaller:

	pip install pyinstaller
	pyinstaller --version

### 3-) Create active response script

Create an active response script "kill.py" to remove a file from the Windows endpoint:

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

### 4-) Convert the active response Python script kill.py to a Windows executable application

Convert the active response Python script kill.py to a Windows executable application. Run the following PowerShell command as an administrator to create the executable:

	pyinstaller -F \path\kill.py

Take note of the path where pyinstaller created kill.exe

### 5-) Move the executable file

Move the executable file remove-threat.exe to the C:\Program Files (x86)\ossec-agent\active-response\bin directory.

### 6-) Restart Wazuh Agent
Restart the Wazuh agent to apply the changes. Run the following PowerShell command as an administrator:

	Restart-Service -Name wazuh


## Configurations on Manager

### 1-) Creating the CDB list

A CDB list is a text file with key:value pairs. Each pair must be on a single line, and the keys must be unique. However, values are optional. In this post, We create a CDB List for unwanted software vendors.

To do this, create a file called malware-hashes in /var/ossec/etc/lists/ on the manager.

	vi /var/ossec/etc/lists/unwanted-software-vendors

Add your malicious MD5s to the file.:

	Brave Software, Inc.:
	Node.js:

We proceed to add the created CDB list to the manager ossec.conf so it is available for use in rules. The list is added to the manager by specifying the path to the list in the <ruleset> block.

	<list>etc/lists/unwanted-software-vendors</list>

### 2-) Detecting Unwanted Software Vendors on local_rules.xml
Once the list has been added to the configuration file, we proceed to create a custom rule in /var/ossec/etc/rules/local_rules.xml to alert when the Vendors of a started process is found in the Unwanted Software Lists.

	<<group name="windows, sysmon, sysmon_process-anomalies,">
		<rule id="100000" level="5">
			<if_group>sysmon_event1</if_group>
			<field name="win.eventdata.image">\.</field>
			<description>$(win.system.providerName) - Process Creation - $(win.eventdata.originalFileName)</description>
		</rule>

		<rule id="100001" level="5">
			<if_group>sysmon_event8</if_group>
			<field name="win.eventdata.sourceImage">\.</field>
			<description>$(win.system.providerName) - Suspicious Process $(win.eventdata.originalFileName) created a remote thread</description>
		</rule>

		<rule id="100002" level="5">
			<if_group>sysmon_event_10</if_group>
			<field name="win.eventdata.sourceImage">\.</field>
			<description>$(win.system.providerName) - Suspicious Process $(win.eventdata.originalFileName) accessed $(win.eventdata.targetImage)</description>
		</rule>
		<rule id="100003" level="12">
			<if_sid>100000</if_sid>
			<list field="win.eventdata.company" lookup="match_key">etc/lists/unwanted-software-vendors</list>
			<description>$(win.system.providerName) - Event 1: Process $(win.eventdata.description) started but not allowed by the software policy.</description>
			<mitre>
				<id>T1036</id>
			</mitre>
			<options>no_full_log</options>
			<group>sysmon_event1,software_policy</group>
		</rule>
	</group>

### 3-) Define Active Response on ossec.conf

Now that the active response executable has been placed in the bin folder on the agent, we proceed to configure the manager to trigger an active response when the unwanted software vendors detection rule is triggered. In the manager configuration file, we add the following block in the ossec_config block:

	<command>
		<name>pssuspend</name>
		<executable>kill.exe</executable>
		<timeout_allowed>no</timeout_allowed>
	</command>

	<active-response>
		<disabled>no</disabled>
		<level>10</level>
		<command>pssuspend</command>
		<location>local</location>
		<rules_group>software_policy</rules_group>
	</active-response>

### 4-) Restart Wazuh Manager
Restart the Wazuh manager to apply the configuration changes:

	sudo systemctl restart wazuh-manager

