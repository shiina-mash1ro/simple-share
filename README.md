# simple-share

需要访问的IP: 192.168.1.1 端口: 80

server ip 192.168.1.50
client ip 192.168.1.51

运行服务端
```
server -address 192.168.1.1:80 -password 123456 -listen-port 33333
```

运行客户端
```
client -address 192.168.1.50:33333 -password 123456 -listen-port 33334
```

或者

```
client -address 192.168.1.50:33333 -password 123456 -listen-port 33334 -gen-config

eyJhZGRyZXNzIjoiMTkyLjE2OC4xLjUwOjMzMzMzIiwicGFzc3dvcmQiOiIxMjM0NTYiLCJsaXN0ZW5fcG9ydCI6MzMzMzR9
```
将结果保存到任意 .txt 文件
双击打开 client
