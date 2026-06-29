def get_mitre_mapping():

    return {
        "Brute Force": {
            "id": "T1110",
            "tactic": "Credential Access"
        },

        "PowerShell": {
            "id": "T1059.001",
            "tactic": "Execution"
        },

        "User Creation": {
            "id": "T1136",
            "tactic": "Persistence"
        },

        "Ransomware": {
            "id": "T1486",
            "tactic": "Impact"
        },

        "IOC": {
            "id": "T1583",
            "tactic": "Resource Development"
        }
    }