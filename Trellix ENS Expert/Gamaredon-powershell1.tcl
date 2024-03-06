# PowerPunch malware registery persistance
# # APT Group: Gamerdon
# Author: Adam Burnett; @InfosecEagle; alburnett[at]gmail{.}com
Rule {
	Initiator {
		Match PROCESS {
			Include OBJECT_NAME {-v "**"} 
			
			}
		}
	
	Target {
		Match VALUE {
			Include -access "CREATE WRITE"
			Include OBJECT_NAME {-v "HKCU\\Network\\ip"}
			Include OBJECT_NAME {-v "HKCU\\Network\\key"}
			Include OBJECT_NAME {-v "HKCU\\Network\\vol"}
			Include OBJECT_NAME {-v "HKCU\\Network\\wc"}
			Include OBJECT_NAME {-v "HKCU\\Network\\xor"}
			Include OBJECT_NAME {-v "HKCU\\Network\\run"}
			}
		}
	}