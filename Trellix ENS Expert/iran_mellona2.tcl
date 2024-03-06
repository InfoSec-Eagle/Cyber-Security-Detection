# Refrence: https://www.microsoft.com/en-us/security/blog/2022/09/08/microsoft-investigates-iranian-attacks-against-the-albanian-government/
# APT Group: Hazel Sandstorm; Helix Kitten; Oilrig
# Author: Adam Burnett; @InfosecEagle; alburnett[at]gmail{.}com

Regritsry write:
Rule {
	Initiator {
		Match PROCESS {
			Include OBJECT_NAME {-v "**"}
			}
		}
	
	Target {
		Match VALUE {
			Include -access "CREATE WRITE"
			Include OBJECT_NAME {-v "HKLM\\SYSTEM\\CurrentControlSet\\Services\\RawDisk3\\**"}
		}
	}
}