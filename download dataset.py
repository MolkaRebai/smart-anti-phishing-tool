import requests

response = requests.get("http://data.phishtank.com/data/online-valid.csv")

with open("phishing_urls.csv", "wb") as f:
    f.write(response.content)
