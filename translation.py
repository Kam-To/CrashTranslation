import sys
import os
import argparse
import pathlib
import json

'''
Translating symbolicated Apple JSON format crash log into our old friends :)
'''

def translation(ips_header, payload):
	content = ""
	ips_header_json = json.loads(ips_header)
	payload_json = json.loads(payload)
	content += buildHeader(ips_header_json, payload_json)

	used_binary_images = payload_json["usedImages"]

	# asi info
	if "asi" in payload_json:
		asi = payload_json["asi"]
		content += "Application Specific Information:\n\n\n{}\n{}\n{}\n".format(''.join(asi["CoreFoundation"]), ''.join(asi["libsystem_c.dylib"]), ''.join(asi["libc++abi.dylib"]))

	# last_exception_backtrace
	if "lastExceptionBacktrace" in payload_json:
		last_exception_backtrace = payload_json["lastExceptionBacktrace"]
		if len(last_exception_backtrace) > 0:
				content += "Last Exception Backtrace:\n"
				content += buildFrameStack(last_exception_backtrace, used_binary_images)
	
	# threads backtrace
	threads = payload_json["threads"]
	for idx, thread in enumerate(threads):
		content += "\n"
		thread_info = threadNameInfo(idx, thread)
		content += thread_info
		# check if this thread causing crash
		if "triggered" in thread and thread["triggered"] == True:
			content += "Thread {} Crashed:\n".format(idx)
			triggered_thread_idx = idx
		else:
			content += "Thread {}:\n".format(idx)
		content += buildFrameStack(thread["frames"], used_binary_images)

	content += "\n"

	# triggered thread status
	triggered_thread = threads[triggered_thread_idx]
	if "threadState" in triggered_thread:
		content += buildThreadState(triggered_thread_idx, triggered_thread)

	content += buildBinaryImages(used_binary_images)
	content += "\nEOF"
	return content

def buildHeader(ips_header_json, payload_json):
	content = ""
	content += "Incident Identifier: {}\n".format(ips_header_json["incident_id"])
	content += "CrashReporter Key:   {}\n".format(payload_json["crashReporterKey"])
	content += "Hardware Model:      {}\n".format(payload_json["modelCode"])
	content += "Process:             {} [{}]\n".format(payload_json["procName"], payload_json["pid"])
	content += "Path:                {}\n".format(payload_json["procPath"])
	bundleInfo = payload_json["bundleInfo"]
	content += "Identifier:          {}\n".format(bundleInfo["CFBundleIdentifier"])
	content += "Version:             {} ({})\n".format(bundleInfo["CFBundleShortVersionString"], bundleInfo["CFBundleVersion"])
	content += "Code Type:           {} (Native(?))\n".format(payload_json["cpuType"]) #  (Native) not sure for this
	content += "Role:                {}\n".format(payload_json["procRole"])
	content += "Parent Process:      {} [{}]\n".format(payload_json["parentProc"], payload_json["parentPid"])
	content += "Coalition:           {} [{}]\n".format(payload_json["coalitionName"], payload_json["coalitionID"])
	content += "\n"
	content += "Date/Time:           {}\n".format(payload_json["captureTime"])
	content += "Launch Time:         {}\n".format(payload_json["procLaunch"])
	content += "OS Version:          {}\n".format(ips_header_json["os_version"])
	content += "Release Type:        {}\n".format(payload_json["osVersion"]["releaseType"])
	content += "Baseband Version:    {}\n".format(payload_json["basebandVersion"])
	content += "Report Version:      104(?)" # not sure
	content += "\n"
	exception = payload_json["exception"]
	content += "Exception Type:  {} ({})\n".format(exception["type"], exception["signal"])
	content += "Exception Codes: {}\n".format(exception["codes"])
	content += "Exception Note:  EXC_CORPSE_NOTIFY(?)\n"
	content += "Triggered by Thread:  {}\n".format(payload_json["faultingThread"])
	content += "\n"
	return content

def buildFrameStack(frames, binarys):
	content = ""
	for idx, frame in enumerate(frames):
		frame_belong_to_image = binarys[frame["imageIndex"]]
		address = frame["imageOffset"] + frame_belong_to_image["base"]
		if "symbol" in frame:
			content += "{:<4}{:<40}0x{:x} {} + {}\n".format(idx, frame_belong_to_image["name"], address, frame["symbol"], frame["symbolLocation"])
		else:
			content += "{:<4}{:<40}0x{:x} 0x{:x} + {}\n".format(idx, frame_belong_to_image["name"], address, frame_belong_to_image["base"], frame["imageOffset"])
	return content

def threadNameInfo(idx, threadObj):
	name = ""
	if "name" in threadObj:
		name = threadObj["name"]
	elif "queue" in threadObj:
		name = threadObj["queue"]
	if len(name) > 0:
		content = "Thread {} name:  {}\n".format(idx, name)
	else:
		content = ""
	return content

def buildThreadState(triggered_thread_idx, triggered_thread):
	# assuming thread_state["flavor"] is always "ARM_THREAD_STATE64"
	content = "Thread {} crashed with ARM Thread State (64-bit):\n".format(triggered_thread_idx)

	thread_state = triggered_thread["threadState"]
	x_registers = thread_state["x"]
	for idx, x in enumerate(x_registers):
		content += "{:>6}: 0x{:016x}".format("x" + str(idx), x["value"])
		if idx % 4 == 3:
			content += "\n"
	non_general_registers_name = ["fp", "lr", "sp", "pc", "cpsr", "far", "esr"]
	for idx, name in enumerate(non_general_registers_name):
		register = thread_state[name]
		content += "{:>6}: 0x{:016x}".format(name, x["value"])
		if "description" in register:
			content += register["description"]
		if idx % 3 == 2:
			content += "\n"
	content += "\n"
	return content

def buildBinaryImages(used_binary_images):
	content = "\nBinary Images:\n"
	for image in used_binary_images:
		content += "       0x{:x} - 0x{:x} {} {}  <{}> {}\n".format(image["base"], image["base"] + image["size"], image["name"], image["arch"], image["uuid"], image["path"])
	return content

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Translating symbolicated Apple JSON format crash log into our old friends :)")
	parser.add_argument("-i", "--input", dest="input", type=pathlib.Path, help="input ips path")
	parser.add_argument("-o", "--output", dest="output", type=pathlib.Path, help="output path")
	args = parser.parse_args()
	if os.path.isfile(args.input) :
		with open(args.input, "r") as f:
		    data = f.read()
		ips_header, payload = data.split('\n', 1)
		newData = translation(ips_header, payload)
		with open(args.output, "w") as f:
			f.write(newData)
	else:
		print("😡 There is no input file for translation :(")

