# Refrence: https://www.microsoft.com/en-us/security/blog/2022/09/08/microsoft-investigates-iranian-attacks-against-the-albanian-government/
# APT Group: Hazel Sandstorm; Helix Kitten; Oilrig
# Author: Adam Burnett; @InfosecEagle; alburnett[at]gmail{.}com

malware executing malware:

Rule {
	Initiator {
		Match PROCESS {
			Include OBJECT_NAME {-v "Mellona.exe"}
			
			}
		}
	
	Target {
		Match FILE {
			include -access "EXECUTE"
			include OBJECT_NAME {"c:\\ProgramData\\Microsoft\\Windows\\GoXML.exe"}
			}
		}
	}
