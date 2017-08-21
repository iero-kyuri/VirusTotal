from vt import vt

with open("apikey.txt","r") as f:
  apikey = f.read().strip()

VT = vt(apikey)

# scan
test_file = "test.txt"
scan = VT.scan_file(test_file)
rescan = VT.rescan_file(test_file)

url = "https://www.google.com"
scan_url = VT.scan_url(url)

# result
## You have to wait a few minutes after scan.
report = VT.get_report(test_file)
url_report = VT.get_url_report(url)

malicious_count = 0
for attr in report["scans"].keys():
  if report["scans"][attr]["detected"]:
    malicious_count += 1
print "[+] malicious count",malicious_count

malicious_count = 0
for attr in url_report["scans"].keys():
  if url_report["scans"][attr]["detected"]:
    malicious_count += 1
print "[+] malicious count",malicious_count
