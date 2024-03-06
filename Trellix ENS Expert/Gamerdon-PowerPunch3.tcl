# PowerPunch malware registery persistance
# APT Group: Gamerdon
# Author == Adam Burnett; @infoseceagle

Rule {
	Initiator {
		Match PROCESS {
			Include OBJECT_NAME {-v "powershell.exe"}
		}
	}
	Target {
		Match FILE {
			Include -access "CREATE"
			Include OBJECT_NAME {-v "HKCU:\\System\\executer"}
			Include OBJECT_NAME {-v "HKCU:\\System\\executer"}
			Include OBJECT_NAME {-v "HKCU:\\System\\ip"}
			Include OBJECT_NAME {-v "HKCU:\\System\\knoc"}
			Include OBJECT_NAME {-v "HKCU:\\System\\prepare"}
			Include OBJECT_NAME {-v "HKCU:\\System\\result_code"}
			Include OBJECT_NAME {-v "HKCU:\\System\\run"}
			Include OBJECT_NAME {-v "HKCU:\\System\\save"}
			Include OBJECT_NAME {-v "HKCU:\\System\\search"}
			Include OBJECT_NAME {-v "HKCU:\\System\\SetLnk"}
			Include OBJECT_NAME {-v "HKCU:\\System\\update"}
		}
	}
}