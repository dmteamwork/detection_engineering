import tomllib
import os
import json

techniques = {}

# Walk through all TOML detection rules
for root, dirs, files in os.walk("detections/"):

    for file in files:

        if not file.endswith(".toml"):
            continue

        full_path = os.path.join(root, file)

        try:
            with open(full_path, "rb") as f:
                alert = tomllib.load(f)

            # Ensure rule exists
            if "rule" not in alert:
                print(f"[!] Missing [rule] section: {full_path}")
                continue

            rule = alert["rule"]

            # Skip rules without MITRE ATT&CK mappings
            if "threat" not in rule:
                print(f"[!] No threat mapping: {full_path}")
                continue

            # Iterate through all threats
            for threat in rule["threat"]:

                tactic = threat.get("tactic", {}).get("name", "unknown")

                # Skip malformed threat entries
                if "technique" not in threat:
                    continue

                # Iterate through techniques
                for technique in threat["technique"]:

                    technique_id = technique.get("id")

                    if not technique_id:
                        continue

                    # Add / increment parent technique
                    if technique_id not in techniques:
                        techniques[technique_id] = {
                            "techniqueID": technique_id,
                            "tactic": tactic.lower(),
                            "score": 1,
                            "color": "",
                            "comment": "",
                            "enabled": True,
                            "metadata": [],
                            "links": [],
                            "showSubtechniques": True
                        }
                    else:
                        techniques[technique_id]["score"] += 1

                    # Handle subtechniques if present
                    if "subtechnique" in technique:

                        for sub in technique["subtechnique"]:

                            sub_id = sub.get("id")

                            if not sub_id:
                                continue

                            if sub_id not in techniques:
                                techniques[sub_id] = {
                                    "techniqueID": sub_id,
                                    "tactic": tactic.lower(),
                                    "score": 1,
                                    "color": "",
                                    "comment": "",
                                    "enabled": True,
                                    "metadata": [],
                                    "links": [],
                                    "showSubtechniques": False
                                }
                            else:
                                techniques[sub_id]["score"] += 1

        except Exception as e:
            print(f"[!] Error processing {full_path}: {e}")

# Build ATT&CK Navigator layer
navigator = {
    "name": "Custom Detections",
    "versions": {
        "attack": "13",
        "navigator": "4.8.2",
        "layer": "4.4"
    },
    "domain": "enterprise-attack",
    "description": "",
    "filters": {
        "platforms": [
            "Linux",
            "macOS",
            "Windows",
            "Network",
            "PRE",
            "Containers",
            "Office 365",
            "SaaS",
            "Google Workspace",
            "IaaS",
            "Azure AD"
        ]
    },
    "sorting": 0,
    "layout": {
        "layout": "side",
        "aggregateFunction": "average",
        "showID": False,
        "showName": True,
        "showAggregateScores": False,
        "countUnscored": False
    },
    "hideDisabled": False,
    "techniques": list(techniques.values()),
    "gradient": {
        "colors": [
            "#ff6666ff",
            "#ffe766ff",
            "#8ec843ff"
        ],
        "minValue": 0,
        "maxValue": 3
    },
    "legendItems": [],
    "metadata": [],
    "links": [],
    "showTacticRowBackground": False,
    "tacticRowBackground": "#dddddd",
    "selectTechniquesAcrossTactics": True,
    "selectSubtechniquesWithParent": False
}

# Ensure output directory exists
os.makedirs("metrics", exist_ok=True)

# Write navigator layer
output_path = "metrics/navigator.json"

with open(output_path, "w") as f:
    json.dump(navigator, f, indent=4)

print(f"[+] Navigator layer written to: {output_path}")
<<<<<<< HEAD
print(f"[+] Total techniques/subtechniques: {len(techniques)}")
=======
print(f"[+] Total techniques/subtechniques: {len(techniques)}")
>>>>>>> 66a243d17f4777a3658c11e0a1ba60e07efa1584
