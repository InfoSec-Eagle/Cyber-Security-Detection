# PowerPunch malware registery persistance
# APT Group: Gamerdon
# Author: Adam Burnett; @InfosecEagle; alburnett[at]gmail{.}com

Rule {
	Initiator {
		Match PROCESS {
			Include OBJECT_NAME {-v "powershell.exe"}
		}
	}
	Target {
		Match VALUE {
			Include -access "CREATE WRITE"
			Include OBJECT_NAME {-v "HKCU\\System\\run"}
			Include REGVAL_DATA -type STRING {-v "$Key='HKCU:\\System';while($true)[environment]"}
		}
	}
}
