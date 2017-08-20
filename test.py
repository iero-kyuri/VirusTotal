from vt import vt

with open("apikey.txt","r") as f:
  apikey = f.read().strip()

VT = vt(apikey)

test_file = "test.txt"
scan = VT.scan_file(test_file)
rescan = VT.rescan_file(test_file)

# You have to wait a few minutes.
report = VT.get_report(test_file)

url = "https://www.google.com"
scan_url = VT.scan_url(url)


