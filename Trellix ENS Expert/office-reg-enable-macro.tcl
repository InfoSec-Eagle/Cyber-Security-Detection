# "Inspration": https://www.bitdefender.com/en-us/blog/businessinsights/uac-0063-cyber-espionage-operation-expanding-from-central-asia
# "Inspration": https://blog.sekoia.io/double-tap-campaign-russia-nexus-apt-possibly-related-to-apt28-conducts-cyber-espionage-on-central-asia-and-kazakhstan-diplomatic-relations/#h-iii-hatvibe-and-cherryspy-infection-chain
# APT Group: Generic
# Author: Adam Burnett; @InfosecEagle; alburnett[at]gmail{.}com
# Notes: This should trigger for office macros modifying the registry to enable macros. Currently unsure of the performance hit this rule may induce.


Macros registry write:

Rule {
	Initiator {
		Match PROCESS {
			Include OBJECT_NAME {-v "c:\\Program Files\\Microsoft Office\\root\\Office*\\winword.exe"}
			Include OBJECT_NAME {-v "c:\\Program Files\\Microsoft Office\\root\\Office*\\excel.exe"}
			Include OBJECT_NAME {-v "c:\\Program Files\\Microsoft Office\\root\\Office*\\powerpnt.exe"}
			Include OBJECT_NAME {-v "c:\\Program Files\\Microsoft Office\\root\\Office*\\msaccess.exe"}
			Include OBJECT_NAME {-v "c:\\Program Files\\Microsoft Office\\root\\Office*\\onenote.exe"}
			Include OBJECT_NAME {-v "c:\\Program Files\\Microsoft Office\\root\\Office*\\onenotem.exe"}
			Include OBJECT_NAME {-v "c:\\Program Files\\Microsoft Office\\root\\Office*\\mspub.exe"}
			Include OBJECT_NAME {-v "c:\\Program Files\\Microsoft Office\\root\\Office*\\outlook.exe"} # ??


			}
		}
	
	Target {
		Match VALUE {
			Include -access "CREATE WRITE"
			Include OBJECT_NAME {-v "HKCU\\Software\\Policies\\Microsoft\\Office\\*\*\\Security\\AccessVBOM"}
		}
	}
}