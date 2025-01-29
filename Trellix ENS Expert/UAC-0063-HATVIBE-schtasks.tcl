# Refrence: https://www.bitdefender.com/en-us/blog/businessinsights/uac-0063-cyber-espionage-operation-expanding-from-central-asia
# Refrence: https://blog.sekoia.io/double-tap-campaign-russia-nexus-apt-possibly-related-to-apt28-conducts-cyber-espionage-on-central-asia-and-kazakhstan-diplomatic-relations/#h-iii-hatvibe-and-cherryspy-infection-chain
# APT Group: UAC-0063

# Author: Adam Burnett; @InfosecEagle; alburnett[at]gmail{.}com
# Notes: This should trigger for mshat[.]exe running schtasks[.]exe. Effectivly broadning the detection abilities of this rule.


Hatvibe scheduled task:

Rule {
	Initiator {
		Match PROCESS {
			Include OBJECT_NAME {-v "c:\\Windows\\*\\mshta.exe"}

			}
		}

        Target {
		Match Process {
			Include OBJECT_NAME {-v "schtasks.exe"}
			Include PROCESS_CMD_LINE { -v "*/create*" }
            Include PROCESS_CMD_LINE { -v "*/delete*" }
            Include PROCESS_CMD_LINE { -v "*/change*" }
		}
    }
}