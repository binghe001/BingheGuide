# 利用Metasploit找出SCADA服务器

## 注册账号

首先，我们在https://www.shodan.io上注册一个账号

## 获取API Key

注册账号成功之后，我们获取一个免费的API Key

![img](https://img-blog.csdnimg.cn/20190117213554609.png)

## 在Metasploit中找出采用罗克韦尔自动化技术的SCADA系统

```
msfconsole
use auxiliary/gather/shodan_search
show options
set SHODAN_APIKEY 第2步获取的API Key
set QUERY Rockwell
run
```

具体操作如下：

```
msf > use auxiliary/gather/shodan_search
msf auxiliary(gather/shodan_search) > show options

Module options (auxiliary/gather/shodan_search):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   DATABASE       false            no        Add search results to the database
   MAXPAGE        1                yes       Max amount of pages to collect
   OUTFILE                         no        A filename to store the list of IPs
   Proxies                         no        A proxy chain of format type:host:port[,type:host:port][...]
   QUERY                           yes       Keywords you want to search for
   REGEX          .*               yes       Regex search for a specific IP/City/Country/Hostname
   SHODAN_APIKEY                   yes       The SHODAN API key
   SSL            false            no        Negotiate SSL/TLS for outgoing connections

msf auxiliary(gather/shodan_search) > set SHODAN_APIKEY  第2步获取的API Key
SHODAN_APIKEY => dRDBajzYMt9EPV2I5i87f3YWhfykY43p
msf auxiliary(gather/shodan_search) > set QUERY Rockwell
QUERY => Rockwell
msf auxiliary(gather/shodan_search) > run

[*] Total: 7351 on 74 pages. Showing: 1 page(s)
[*] Collecting data, please wait...

Search Results
==============

 IP:Port                City               Country             Hostname
 -------                ----               -------             --------
 104.169.148.106:44818  Lewiston           United States       
 107.85.58.132:44818    N/A                United States       
 107.85.58.184:44818    N/A                United States       
 108.95.125.62:44818    Excelsior Springs  United States       108-95-125-62.lightspeed.mssnks.sbcglobal.net
 124.199.70.151:44818   Tainan             Taiwan              124-199-70-151.HINET-IP.hinet.net
 129.24.204.161:44818   Albuquerque        United States       ssc-0006.unm.edu
 142.55.112.203:44818   Oakville           Canada              br-c147-plc03.ddi.sheridanc.on.ca
 166.130.151.114:44818  Atlanta            United States       mobile-166-130-151-114.mycingular.net
 166.130.155.138:44818  Atlanta            United States       mobile-166-130-155-138.mycingular.net
 166.130.174.51:44818   Atlanta            United States       mobile-166-130-174-51.mycingular.net
 166.130.71.137:44818   Atlanta            United States       mobile-166-130-71-137.mycingular.net
 166.130.72.51:44818    Atlanta            United States       mobile-166-130-72-51.mycingular.net
 166.131.38.86:44818    N/A                United States       mobile-166-131-38-86.mycingular.net
 166.139.173.118:44818  N/A                United States       118.sub-166-139-173.myvzw.com
 166.139.78.48:44818    N/A                United States       48.sub-166-139-78.myvzw.com
 166.141.166.213:44818  N/A                United States       213.sub-166-141-166.myvzw.com
 166.142.163.179:44818  N/A                United States       179.sub-166-142-163.myvzw.com
 166.142.214.167:44818  N/A                United States       167.sub-166-142-214.myvzw.com
 166.142.223.87:44818   N/A                United States       87.sub-166-142-223.myvzw.com
 166.148.138.164:44818  N/A                United States       164.sub-166-148-138.myvzw.com
 166.150.224.175:44818  N/A                United States       175.sub-166-150-224.myvzw.com
 166.150.235.165:44818  N/A                United States       165.sub-166-150-235.myvzw.com
 166.152.102.3:44818    N/A                United States       3.sub-166-152-102.myvzw.com
 166.152.146.81:44818   N/A                United States       81.sub-166-152-146.myvzw.com
 166.152.7.95:44818     N/A                United States       95.sub-166-152-7.myvzw.com
 166.152.86.244:44818   N/A                United States       244.sub-166-152-86.myvzw.com
 166.152.88.177:44818   N/A                United States       177.sub-166-152-88.myvzw.com
 166.155.192.83:44818   N/A                United States       83.sub-166-155-192.myvzw.com
 166.155.230.179:44818  N/A                United States       179.sub-166-155-230.myvzw.com
 166.155.244.192:44818  N/A                United States       192.sub-166-155-244.myvzw.com
 166.155.68.30:44818    N/A                United States       30.sub-166-155-68.myvzw.com
 166.156.252.231:44818  N/A                United States       231.sub-166-156-252.myvzw.com
 166.157.134.23:44818   N/A                United States       23.sub-166-157-134.myvzw.com
 166.157.180.145:44818  N/A                United States       145.sub-166-157-180.myvzw.com
 166.157.211.136:44818  N/A                United States       136.sub-166-157-211.myvzw.com
 166.165.60.50:44818    N/A                United States       50.sub-166-165-60.myvzw.com
 166.165.81.185:44818   N/A                United States       185.sub-166-165-81.myvzw.com
 166.165.81.188:44818   N/A                United States       188.sub-166-165-81.myvzw.com
 166.168.129.250:44818  N/A                United States       250.sub-166-168-129.myvzw.com
 166.168.68.40:44818    N/A                United States       40.sub-166-168-68.myvzw.com
 166.169.25.205:44818   N/A                United States       205.sub-166-169-25.myvzw.com
 166.211.227.248:44818  N/A                United States       248.sub-166-211-227.myvzw.com
 166.239.236.32:44818   N/A                United States       32.sub-166-239-236.myvzw.com
 166.239.24.87:44818    N/A                United States       87.sub-166-239-24.myvzw.com
 166.241.108.53:44818   N/A                United States       53.sub-166-241-108.myvzw.com
 166.246.171.53:44818   N/A                United States       53.sub-166-246-171.myvzw.com
 166.247.38.132:44818   N/A                United States       132.sub-166-247-38.myvzw.com
 166.247.38.228:44818   N/A                United States       228.sub-166-247-38.myvzw.com
 166.247.72.15:44818    N/A                United States       15.sub-166-247-72.myvzw.com
 166.247.72.26:44818    N/A                United States       26.sub-166-247-72.myvzw.com
 166.250.88.74:44818    N/A                United States       74.sub-166-250-88.myvzw.com
 166.254.18.72:44818    N/A                United States       72.sub-166-254-18.myvzw.com
 166.254.21.20:44818    N/A                United States       20.sub-166-254-21.myvzw.com
 166.255.248.118:44818  Bothell            United States       118.sub-166-255-248.myvzw.com
 173.241.180.88:44818   Dickinson          United States       mail.frontiertravelcenter.com
 174.79.107.66:44818    Rogers             United States       mail.our-klan.com
 174.90.225.57:44818    Beaumont           Canada              
 184.13.254.67:44818    Bruceton Mills     United States       static-184-13-254-67.clbg.wv.frontiernet.net
 184.159.33.72:44818    Osceola            United States       184-159-33-72.stat.centurytel.net
 184.188.189.102:44818  Littleton          United States       wsip-184-188-189-102.ks.ks.cox.net
 184.6.175.136:44818    Bassett            United States       tx-184-6-175-136.sta.embarqhsd.net
 185.183.222.174:44818  Ceuti              Spain               185.183.222.174.dyn.user.borecom.com
 187.201.128.237:44818  Zapopan            Mexico              dsl-187-201-128-237-dyn.prod-infinitum.com.mx
 192.186.64.242:44818   Windsor            Canada              d192-186-64-242.db.static.comm.cgocable.net
 192.199.57.83:44818    Red Earth          Canada              
 198.0.121.49:44818     N/A                United States       MAIL.GFMCORP.COM
 198.163.95.77:44818    N/A                United States       
 198.35.56.250:44818    N/A                United States       
 199.167.142.76:161     N/A                Canada              
 199.79.231.236:44818   Augusta            United States       
 2.143.95.44:44818      Perdices           Spain               44.red-2-143-95.dynamicip.rima-tde.net
 2.55.70.153:44818      Jerusalem          Israel              
 207.195.130.150:44818  Rexford            United States       207.195.130.150-st-tel.net
 208.98.195.106:44818   Calgary            Canada              
 211.75.65.156:44818    Dongning           Taiwan              211-75-65-156.HINET-IP.hinet.net
 213.3.8.120:44818      N/A                Switzerland         120.8.3.213.static.wline.lns.sme.cust.swisscom.ch
 216.115.198.94:44818   Rocky Gap          United States       
 24.111.213.227:44818   Dickinson          United States       24-111-213-227-static.midco.net
 24.86.129.129:44818    Vancouver          Canada              S01060030440868d3.vc.shawcable.net
 50.205.167.178:44818   Elkhart            United States       50-205-167-178-static.hfc.comcastbusiness.net
 50.247.170.211:44818   Melrose Park       United States       50-247-170-211-static.hfc.comcastbusiness.net
 58.246.115.189:161     Shanghai           China               
 59.20.136.91:44818     Busan              Korea, Republic of  
 63.88.122.58:44818     Richmond           United States       
 70.166.134.53:44818    Fayetteville       United States       wsip-70-166-134-53.fv.ks.cox.net
 70.186.236.43:44818    Lowell             United States       wsip-70-186-236-43.ks.ks.cox.net
 70.28.254.80:44818     Dundalk            Canada              
 70.62.46.230:44818     Columbus           United States       
 70.88.243.93:44818     N/A                United States       70-88-243-93-ma-nh-me-ne.hfc.comcastbusiness.net
 75.228.158.242:44818   N/A                United States       242.sub-75-228-158.myvzw.com
 76.70.223.14:44818     N/A                Canada              
 77.210.193.171:44818   Barcelona          Spain               
 77.211.19.36:44818     Salamanca          Spain               
 78.116.231.225:44818   Lombez             France              225.231.116.78.rev.sfr.net
 85.120.40.73:44818     N/A                Romania             
 91.149.55.49:44818     N/A                Norway              
 96.57.38.114:44818     Saint James        United States       ool-60392672.static.optonline.net
 96.70.239.109:44818    Boston             United States       96-70-239-109-static.hfc.comcastbusiness.net
 96.84.106.227:44818    Chicago            United States       96-84-106-227-static.hfc.comcastbusiness.net
 98.164.37.98:44818     Skiatook           United States       wsip-98-164-37-98.tu.ok.cox.net

[*] Auxiliary module execution completed
```

可以看到找到了很多的SCADA系统。