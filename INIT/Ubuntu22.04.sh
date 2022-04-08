# docker env
apt update
apt install vim gdb wget git curl nmap zsh python3 pip -y
# install pip & ipython 
apt-get install ipython3 -y
# install pwntools
pip3 install pwntools
# install on-my-zsh   
sh -c "$(curl -fsSL https://raw.github.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"
apt-get install gcc-multilib -y
# install peda
cd 
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinits
# pwngdb
cd
git clone https://github.com/scwuaptx/Pwngdb.git
cp ~/Pwngdb/.gdbinit ~/
# install pwndbg
#git clone https://github.com/pwndbg/pwndbg
#cd pwndbg
#./setup.sh
# install one_gadget
apt install ruby ruby-dev -y
apt install gem -y
gem install one_gadget
gem install seccomp-tools
