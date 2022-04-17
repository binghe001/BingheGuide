# kali安装免杀工具Veil-Evasion

## Veil Evasion简介

Veil Evasion是一个可执行文件，它被用来生成Metasploit的payload，能绕过常见杀软。

免责声明：本教程目的只是为了教育，我们不对这些东西会如何使用担任何风险，使用它的后果自负。

Veil-Evasion被原生设计为在kali上，但其实存在python环境的系统上应该都能运行。你可以用命令行轻松调用Veil-Evasion，按菜单选项生成payload。在创建payload的时候，Veil-Evasion会询问你是否想把payload文件用Pyinstaller或者Py2Exe转为可执行文件。

## 如何下载Veil Evasion

下载Veil Evasion需要以下命令：

安装git：

```bash
sudo apt-get -y install git
```

git命令行下载Veil Evasion：

```bash
git clone https://github.com/Veil-Framework/Veil-Evasion.git
```

把它移动到opt目录下（可选）：

```bash
mv Veil-Evasion /opt
```

如何安装Veil Evasion

进入Veil Evasion所在目录：

```bash
cd /opt/Veil-Evasion/
```

启动setup脚本开始安装：

```bash
bash setup/setup.sh -s
```

## 