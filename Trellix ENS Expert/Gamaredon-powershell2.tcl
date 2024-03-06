# AAC rule for detecting Gamaredon powershell script
# Uses slightly uniuqe components of the script for identification; should *not be a "blocking"* rule w/o copious testing
# Author: Adam Burnett; @InfosecEagle; alburnett[at]gmail{.}com

Rule {
	Process { 
		Include OBJECT_NAME      { -v "powershell.exe"}
		Include PROCESS_CMD_LINE { -v "* -WInDowsTyle HIdDeN *" }
		Include PROCESS_CMD_LINE { -v "* get-content \"\$homelog.bin\"\|powershell.exe -noprofile*" }
			}
	Target {
		Match SECTION { Include -access "CREATE" }
			}
	}
