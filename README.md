# SberCloud
 
Simple BFF web-application integrated with Sbercloud monitoring API
 
## Notice
 
Project represents only API for mobile devices. You can check them here:
 
- Main iOS application: https://github.com/perekrist/SberCloud
 
- Alternative Android app: https://github.com/somnoynadno/SberCloud
 
## Deployment
 
### Linux server

```bash

git clone https://github.com/ifrag/SberCloud.git
cd SberCloud
export DATABASE_URL={ postgres URI }  # note: it should be replaced
pip3 install -r requirements.txt
python3 sbercloud_backend/main.py
```
Since API would be available on 0.0.0.0:8080/v1/*.


You can also use swagger on 0.0.0.0:8080/static/index.html to
check API.
 
## Troubleshooting
 
Contact me: @ifrag
