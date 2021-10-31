## 安装bcc工具
```shell
echo "deb [trusted=yes] https://repo.iovisor.org/apt/xenial xenial-nightly main"| sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install -y bcc-tools libbcc-examples python-bcc
```
参考：https://www.bookstack.cn/read/sdn-handbook/linux-bpf-bcc.md