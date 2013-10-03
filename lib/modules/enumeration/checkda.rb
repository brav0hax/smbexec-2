require 'poet'

class CheckDA < Poet::Scanner
	self.mod_name = "Check systems for Domain Admin"
	self.description = ""

	def setup
		# Print title
		puts 
		title = "Domain Admins Status"
		puts color_header(title)

		@da = {}
	end

	def run(username, password, host)
		# call check4da method to determine if DA is logged in
		domain_admins = []
		capture_stderr('/dev/null') {
			domain_admins = check4da(username, password, host)	
		}

		if domain_admins
			@da[:"#{host}"] = domain_admins
			@success = @success + domain_admins.length
		else
			@failed = @failed + 1
		end
	end

	def finish
		puts "\nDA found: #{@success}\n\n"
		print "Press enter to Return to Enumeration Menu"
		gets

		store_banner("DA found: #{@success}", :da)
		store_opts(@da, :da)
	end
end