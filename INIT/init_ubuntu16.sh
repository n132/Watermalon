# Passwd
sudo passwd
# namp(ncat)
sudo apt-get install -y nmap
# update and upgrade
sudo apt-get update
sudo apt-get upgrade
# remove useless software
sudo apt-get remove libreoffice-common unity-webapps-common thunderbird totem rhythmbox simple-scan gnome-mahjongg aisleriot gnome-mines cheese transmission-common gnome-orca webbrowser-app deja-dup
sudo apt-get autoremove
# install pip
sudo apt-get install python-pip
# install vim
sudo apt-get install vim
# install ipython
sudo apt-get install ipython
# install pwntools
sudo apt-get install python2.7 python-pip python-dev git libssl-dev libffi-dev build-essential
sudo pip install --upgrade pwntools
# install angr
sudo apt-get install python-dev libffi-dev build-essential
sudo pip install angr
# install zsh
sudo apt-get install zsh
sudo apt-get install git
sudo wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | sh
chsh -s /usr/bin/zsh
# install gcc multiple library
sudo apt-get install gcc-multilib
# install qemu
sudo apt-get install qemu
# install pwndbg
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
# install peda
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
# install one_gadget
sudo apt-get install ruby
sudo apt-get install gem
gem install one_gadget
# install libc-database
git clone https://github.com/niklasb/libc-database
cd libc-database
./get
cd

# pwngdb
cd ~/
git clone https://github.com/scwuaptx/Pwngdb.git 
cp ~/Pwngdb/.gdbinit ~/

# seccomp
cd
sudo apt-get install -y ruby-dev
sudo gem install seccomp-tools
