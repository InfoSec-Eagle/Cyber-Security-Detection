# Refrence: https://www.bitdefender.com/en-us/blog/businessinsights/uac-0063-cyber-espionage-operation-expanding-from-central-asia
# Refrence: https://blog.sekoia.io/double-tap-campaign-russia-nexus-apt-possibly-related-to-apt28-conducts-cyber-espionage-on-central-asia-and-kazakhstan-diplomatic-relations/#h-iii-hatvibe-and-cherryspy-infection-chain
# APT Group: UAC-0063

# Author: Adam Burnett; @InfosecEagle; alburnett[at]gmail{.}com
# Notes: This should trigger for more than UAC-0063's HATVIBE malware; as long as this setting is not already in your environment.

Hatvibe registry write:

Rule {
	Initiator {
		Match PROCESS {
			Include OBJECT_NAME {-v "winword.exe"}

			}
		}
	
	Target {
		Match VALUE {
			Include -access "CREATE WRITE"
			Include OBJECT_NAME {-v "HKCU\\Software\\Policies\\Microsoft\\Office\\*\Word\\Security\\AccessVBOM"}
		}
	}
}