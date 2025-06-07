import requests

url = "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging-all.rules"
response = requests.get(url)

valid_starts = (
    "alert", "pass", "drop", "reject",
    "rejectsrc", "rejectdst", "rejectboth"
)

if response.status_code == 200:
    lines = response.text.splitlines()
    count = 0
    total = 0
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "flow:" in stripped:
            total +=1
            continue
        if any(stripped.startswith(keyword) for keyword in valid_starts):
            if (count % 100 == 0):
                print(stripped)
                print("\n")
            total +=1
            count += 1
    print(f"Number of stateless, uncommented rules: {count}/{total}")
else:
    print(f"Failed to download. Status code: {response.status_code}")
