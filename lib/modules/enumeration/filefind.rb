require 'poet'

class Filefind < Poet::Scanner
	self.mod_name = "File Finder"
	self.description = ""

	def setup
		# Print title
		puts 

		@timeout = 0

		# Get valid path
		print "Enter path to file or list of items or look for #{color_banner('[unattend.txt, unattend.xml, sysprep.*]')} : "
		ext = rgets
		if ext.empty?
			ext = "unattend.txt, unattend.xml, sysprep.*"
		elsif File.file? ext
			temp = []
			File.open(ext, "r").each_line {|line| temp << line}
			print_good("File #{ext} parsed, #{temp.length} items found")
			ext = temp.join(',')
			puts
		end
		@command = ''
		ext.split(',').each {|file| @command << " && dir /s /b #{file.strip}"}
		create_folder("#{@log}/loot") unless folder_exists("#{@log}/loot")
		create_folder("#{@log}/loot/filefinder") unless folder_exists("#{@log}/loot/filefinder")
	
		puts
		title = "File Finder"
		puts color_header(title)
	end

	def run(username, password, host)
		smboptions = "//#{host}"
		files_found = ''
		drives = []		
	
		capture_stderr('/dev/null') {
	
			wmic = smbwmic(smboptions, "select Description,DeviceID from Win32_logicaldisk")
			wmic.lines.each do |line|
				next if line =~ /Description|DeviceID/ or not line.include? '|'
				split_line = line.split('|')
				next if split_line[0] =~ /(CD-ROM|Floppy)/
				drives << split_line[1].strip
			end

			# For each drive detected, run the search
			drives.each do |drive|
				# If final one, add uninstall to winexe
				smboptions = "--uninstall #{smboptions}" if drive.eql? drives.last
				find = winexe(smboptions, "CMD /C cd #{drive}\\#{@command}")
				# Continue on if nothing found
				next if find =~ /File Not Found/
				files_found << find
			end
		}

		if files_found.empty? 
			print_bad("#{host.ljust(15)} - File(s) not found")
		else
			if files_found.lines.count > 2
				print_good("#{host.ljust(15)} - #{files_found.lines.count} File(s) found")
			else
				files_print = Array.new
				files_found.each_line {|line| files_print << line.split('\\').last.chomp}
				print_good("#{host.ljust(15)} - #{files_print.join(', ')} found")
			end
			@success += files_found.lines.count

			begin
				File.open("#{@log}/loot/filefinder/#{host}_filelist.txt", 'a') { |file| file.write(files_found) }
			rescue
				print_bad("#{host}: Issues Writing to #{@log}")
			end
		end
	end

	def finish
		# Put ending titles
		puts
		puts "Total files found: #{@success}"
		puts "File lists are located in: #{@log}/loot/filefinder/<host>_filelist.txt"
		puts

		# Return to menu
		print "Press enter to Return to Enumeration Menu"
		gets

		# Save to Menu class
		#Menu.update_banner(color_banner("DA found: #{@success}"), :shares)
		#Menu.opts[:shares] = @shares
	end
end