-- Head
local shortport = require "shortport"
local http = require "http"
local string = require "string"
local rand = require "rand"

description = [[ 
	Simple PoC script to scan and acquire CobaltStrike Beacon configurations.
	Based on :
		JPCERT :: cobaltstrikescan.py
		Sentinel-One :: parse_beacon_config.py
		Didier Stevens :: 1768.py
		Roman Emelynaov :: L8_get_beacon.py
]] 

# from : https://github.com/whickey-r7/grab_beacon_config
categories = {"safe"}
author = "Wade Hickey"

-- Rule
portrule = shortport.http

-- Action
local function generate_checksum(input)
--	92 and 93 are options
	local trial = ""
	local total = 0
	local i = 1
	while (total ~= input) do
		total = 0
		trial = rand.random_string(4,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
		for i = 1, 4 do
			total = (total + string.byte(string.sub(trial,i,i))) % 256
			i = i + 1
		end
	end
	return "/" .. trial

end

local function grab_beacon(response)
	local test_string = string.char(0xFF) .. string.char(0xFF) .. string.char(0xFF)
	local return_string = ""
	if (response.status == 200) then
		if (http.response_contains(response, test_string, true)) then
			local offset = string.find(response.rawbody, test_string) + 3
			local endian = "<I"
			local key = string.unpack(endian,response.rawbody,offset)
			local size = string.unpack(endian,response.rawbody,offset+4) ~ key
			local c = string.unpack(endian,response.rawbody,offset+8) ~ key
			local mz = c & 0xffff
			local x = math.floor(2 + (offset / 4))
			local y = math.floor((string.len(response.rawbody)/4)-4)
			local repacked  = ""
			local repacked2 = ""
			for var=x,y do
				a = string.unpack(endian,response.rawbody,var*4)
				b = string.unpack(endian,response.rawbody,var*4+4)
				z = tonumber(a) ~ tonumber(b) 
				repacked = repacked .. string.pack(endian,z ~ 0x2e2e2e2e) --version 4
				repacked2 = repacked2 .. string.pack(endian,z ~ 0x69696969) --version 3
			end
			
			beacontypes = {"0 (HTTP)", "1 (Hybrid HTTP DNS)","2 (SMB)", "3 (Unknown)", "4 (TCP)", "5 (Unknown)", "6 (Unknown)","7 (Unknown)","8 (HTTPS)", "9 (Unknown)","10 (Bind TCP)"}
			accesstypes = {"0 (Unknown)","1 (Use direct connection)", "2 (Use IE settings)","3 (Unknown)", "4 (Use proxy server)"}
			local beacontype_index = string.find(repacked,"\x00\x01\x00\x01\x00\x02",1,true)
			local beacontype2_index = string.find(repacked2, "\x00\x01\x00\x01\x00\x02",1,true)
			--Version checking
			if (beacontype_index) then
				local beacontype = string.unpack(">H",repacked,beacontype_index+6)
				if (beacontype < 11) then
					beacontype = beacontypes[beacontype+1]
				else
					beacontype = beacontype .. " (Unknown)"
				end
				return_string = return_string .. "\nBeaconType: " .. beacontype .. "\n"
			elseif (beacontype2_index) then
				repacked = repacked2
				local beacontype = string.unpack(">H", repacked,beacontype2_index+6)
				if (beacontype < 11) then
					beacontype = beacontypes[beacontype+1]
				else
					beacontype = beacontype .. " (Unknown)"
				end
				return_string = return_string .. "\nBeaconType: " .. beacontype .. "\n"
			else
				return ""
			end

			local port_index = string.find(repacked,"\x00\x02\x00\x01\x00\x02",1,true)
			if (port_index) then
				local port = string.unpack(">H",repacked,port_index + 6)
				return_string = return_string .. "Port: " .. port .."\n"
			end

			local polling_index = string.find(repacked,"\x00\x03\x00\x02\x00\x04",1,true)
			if (polling_index) then
				local polling = string.unpack(">I",repacked,polling_index+6)
				return_string = return_string .."Polling: " .. polling .."\n"
			end

			local jitter_index = string.find(repacked,"\x00\x05\x00\x01\x00\x02",1,true)
			if (jitter_index) then
				local jitter = string.unpack(">H",repacked,string.find(repacked,"\x00\x05\x00\x01\x00\x02",1,true)+6)
				return_string = return_string .. "Jitter: " .. jitter .. "\n" 
			end

			local maxdns_index = string.find(repacked,"\x00\x06\x00\x01\x00\x02",1,true)
			if (maxdns_index) then
				local maxdns = string.unpack(">H",repacked,maxdns_index+6)
				return_string = return_string .. "Maxdns: " .. maxdns .. "\n"
			end
		
			local c2server_index = string.find(repacked,"\x00\x08\x00\x03\x01\x00",1,true)
			if (c2server_index) then
				local c2server = string.unpack("z",repacked,c2server_index+6)
				return_string = return_string .. "C2 Server: " .. c2server .. "\n"
			end

			local useragent_index = string.find(repacked,"\x00\x09\x00\x03\x00\x80",1,true)
			if (useragent_index) then
				local useragent = string.unpack("z",repacked,useragent_index+6)	
				return_string = return_string .. "User Agent: " .. useragent .. "\n"
			end

			local httpmethodpath2_index = string.find(repacked,"\x00\x0a\x00\x03\x00\x40",1,true)
			if (httpmethodpath2_index) then
				local httpmethodpath2 = string.unpack("z",repacked,httpmethodpath2_index+6)
				return_string = return_string .. "HTTP Method Path 2: " .. httpmethodpath2 .. "\n"
			end

			local header1_index = string.find(repacked,"\x00\x0c\x00\x03\x01\x00",1,true)
			if (header1_index) then
				local header1 = string.unpack("z",repacked,header1_index+6)
				return_string = return_string .. "Header1: " .. header1 .. "\n"
			end

			local header2_index = string.find(repacked,"\x00\x0d\x00\x03\x01\x00",1,true)
			if (header2_index) then
				local header2 = string.unpack("z",repacked,header2_index+6)
				return_string = return_string .. "Header2: " .. header2 .. "\n"
			end

			local injectionprocess_index = string.find(repacked,"\x00\x0e\x00\x03\x00\x40",1,true)
			if (injectionprocess_index) then
				local injectionprocess = string.unpack("z",repacked,injectionprocess_index+6)
				return_string = return_string .. "Injection Process: " .. injectionprocess .. "\n"
			end
			
			local pipename_index = string.find(repacked,"\x00\x0f\x00\x03\x00\x80",1,true)
			if (pipename_index) then
				local pipename = string.unpack("z",repacked,pipename_index+6)
				return_string = return_string .. "PipeName: " .. pipename .."\n"
			end
	
			local year_index = string.find(repacked,"\x00\x10\x00\x01\x00\x02",1,true)
			if (year_index) then
				local year = string.unpack(">H",repacked,year_index+6)
				return_string = return_string .. "Year: " .. year .. "\n"
			end
			
			local month_index = string.find(repacked,"\x00\x11\x00\x01\x00\x02",1,true)
			if (month_index) then
				local month = string.unpack(">H",repacked,month_index+6)
				return_string = return_string .. "Month: " .. month .. "\n"
			end

			local day_index = string.find(repacked,"\x00\x12\x00\x01\x00\x02",1,true)
			if (day_index) then
				local day = string.unpack(">H",repacked,day_index+6)
				return_string = return_string .. "Day: " .. day .. "\n"
			end

			local dnsidle_index  = string.find(repacked,"\x00\x13\x00\x02\x00\x04",1,true)
			if (dnsidle_index) then
				local dnsidle  = string.unpack("c4",repacked,dnsidle_index+6)
				return_string = return_string .. "DNS Idle: " .. dnsidle .. "\n"
			end

			local dnssleep_index = string.find(repacked,"\x00\x14\x00\x02\x00\x04",1,true)
			if (dnssleep_index) then
				local dnssleep = string.unpack(">H",repacked,dnssleep_index+6)
				return_string = return_string .. "DNS Sleep: " .. dnssleep .. "\n"
			end

			local method1_index = string.find(repacked,"\x00\x1a\x00\x03\x00\x10",1,true)
			if (method1_index) then
				local method1 = string.unpack("z",repacked,method1_index+6)
				return_string = return_string .. "Method1: " .. method1 .. "\n"
			end

			local method2_index  = string.find(repacked,"\x00\x1b\x00\x03\x00\x10",1,true)
			if (method2_index) then
				local method2  = string.unpack("z",repacked,method2_index+6)
				return_string = return_string .. "Method2: " .. method2 .. "\n"
			end
			
			local spawntox86_index = string.find(repacked,"\x00\x1d\x00\x03\x00\x40",1,true)
			if (spawntox86_index) then
				local spawntox86 = string.unpack("z",repacked,spawntox86_index+6)
				return_string = return_string .. "Spawnto_x86: " .. spawntox86 .. "\n"
			end

			local spawntox64_index = string.find(repacked,"\x00\x1e\x00\x03\x00\x40",1,true)
			if (spawntox64_index) then
				local spawntox64 = string.unpack("z",repacked,spawntox64_index+6)
				return_string = return_string .. "Spawnto_x64: " .. spawntox64 .. "\n"
			end

			local proxyhostname_index = string.find(repacked,"\x00\x20\x00\x03\x00\x80",1,true)
			if (proxyhostname_index) then
				local proxyhostname = string.unpack("z",repacked,proxyhostname_index+6)
				return_string = return_string .. "Proxy_Hostname: " .. proxyhostname .. "\n"
			end

			local proxyusername_index = string.find(repacked,"\x00\x21\x00\x03\x00\x40",1,true)
			if (proxyusername_index) then
				local proxyusername = string.unpack("z",repacked,proxyusername_index+6)
				return_string = return_string .. "Proxy_Username: " .. proxyusername .. "\n"
			end

			local proxypassword_index = string.find(repacked,"\x00\x22\x00\x03\x00\x40",1,true)
			if (proxypassword_index) then
				local proxypassword = string.unpack("z",repacked,proxypassword_index+6)
				return_string = return_string .. "Proxy_Password: " .. proxypassword .. "\n"
			end

			local proxyaccesstype_index = string.find(repacked,"\x00\x23\x00\x01\x00\x02",1,true)
			if (proxyaccesstype_index) then
				local proxyaccesstype = string.unpack(">H",repacked,proxyaccesstype_index+6)
				if (proxyaccesstype < 5) then
					proxyaccesstype = accesstypes[proxyaccesstype + 1]
				else
					proxyaccesstype = proxyaccesstype .. " (Unknown)"
				end
				return_string = return_string .. "Proxy_AccessType: " .. proxyaccesstype .. "\n"
			end

			local createremotethread_index = string.find(repacked,"\x00\x24\x00\x01\x00\x02",1,true)
			if (createremotethread_index) then
				local createremotethread = string.unpack(">H",repacked,createremotethread_index+6)
				return_string = return_string .. "create_remote_thread: " .. createremotethread .. "\n"
			end
		end
	end
	return return_string
end


action = function(host,port)
	local output = ""
	local uri_x86 = generate_checksum(92)
	local uri_x64 = generate_checksum(93)
	local response_x86 = http.get(host,port,uri_x86)
	
	response_x86 = grab_beacon(response_x86)
	local response_x64 = http.get(host,port,uri_x64)
	response_x64 = grab_beacon(response_x64)


	if response_x86 ~= "" then
		output = output .. "\nx86 URI Response: " .. response_x86 .. "\n"

	end
	if response_x64~= "" then
		output = output .. "\nx64 URI Response: " .. response_x64 .. "\n"
	end
	return output
end
