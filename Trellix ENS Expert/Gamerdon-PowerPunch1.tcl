Rule {
# PowerPunch malware registery persistance, 1
# Author == Adam Burnett; @infoseceagle
	Initiator {
		Match PROCESS {
			Include OBJECT_NAME {-v "powershell.exe"}
		}
	}
	Target {
		Match VALUE {
			Include -access "CREATE WRITE"
			Include OBJECT_NAME {-v "HKCU\\Software\\Microsoft\\Windows\\CUrrentVersion\\Run\\*"}
			Include REGVAL_DATA -type STRING {-v "$codes = (Get-ItemProperty -Path \"HKCU:\\System\" -Name run)"}
		}
	}
}
