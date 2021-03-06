import requests
import hashlib

class vt:
  def __init__(self,key):
    self.api_key = key

  def scan_file(self,file_path):
    url = "https://www.virustotal.com/vtapi/v2/file/scan"
    files = {'file':(file_path,open(file_path,'rb'))}
    params = {'apikey':self.api_key}
    response = requests.post(url,files=files,params=params)
    json_response = response.json()
    return json_response

  def rescan_file(self,file_path):
    url = "https://www.virustotal.com/vtapi/v2/file/rescan"
    resource = hashlib.sha256(open(file_path,"r").read()).hexdigest()
    params = {'apikey':self.api_key,'resource':resource}
    headers = {
      "Accept-Encoding":"gzip, deflate",
      "User-Agent":"gzip, Kyuri"
    }
    response = requests.get(url,params=params,headers=headers) 
    json_response = response.json()
    return json_response

  def get_report(self,file_path):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    resource = hashlib.sha256(open(file_path,"r").read()).hexdigest()
    params = {'apikey':self.api_key,'resource':resource}
    headers = {
      "Accept-Encoding":"gzip, deflate",
      "User-Agent":"gzip, Kyuri"
    }
    response = requests.get(url,params=params,headers=headers) 
    json_response = response.json()
    return json_response

  def scan_url(self,scan_url):
    url = "https://www.virustotal.com/vtapi/v2/url/scan"
    params = {'apikey':self.api_key,'url':scan_url}
    response = requests.post(url,data=params)
    json_response = response.json()
    return json_response

  def get_url_report(self,scan_url):
    url = "https://www.virustotal.com/vtapi/v2/url/report"
    headers = {
      "Accept-Encoding":"gzip, deflate",
      "User-Agent":"gzip, Kyuri"
    }
    params = {'apikey':self.api_key,'resource':scan_url}
    response = requests.post(url,params=params,headers=headers)
    json_response = response.json()
    return json_response
