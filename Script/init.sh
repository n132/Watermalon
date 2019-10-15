# Passwd
sudo passwd
# namp(ncat)
sudo apt-get install -y nmap
# update and upgrade
sudo apt-get update -y
sudo apt-get upgrade -y
# remove useless software
sudo apt-get remove libreoffice-common unity-webapps-common thunderbird totem rhythmbox simple-scan gnome-mahjongg aisleriot gnome-mines cheese transmission-common gnome-orca webbrowser-app deja-dup -y
sudo apt-get autoremove -y
# install pip
sudo apt-get install python-pip -y
# install vim
sudo apt-get install vim -y
# install ipython
sudo apt-get install ipython -y
# install pwntools
sudo apt-get install python2.7 python-pip python-dev git libssl-dev libffi-dev build-essential -y
sudo pip install --upgrade pwntools
# install angr
sudo apt-get install python-dev libffi-dev build-essential -y
sudo pip install angr
# install zsh
sudo apt-get install zsh -y
sudo apt-get install git -y
sudo apt-get install wget -y
sudo wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | sh
chsh -s /usr/bin/zsh
# install gcc multiple library
sudo apt-get install gcc-multilib -y
# install peda
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
cd ~/
git clone https://github.com/scwuaptx/Pwngdb.git
cp ~/Pwngdb/.gdbinit ~/
# install one_gadget
sudo apt-get install ruby -y
sudo apt-get install gem -y
gem install one_gadget
# install qemu
#sudo apt-get install qemu -y
# install pwndbg
#git clone https://github.com/pwndbg/pwndbg
#cd pwndbg
#./setup.sh
# install libc-database
#git clone https://github.com/niklasb/libc-database
#cd libc-database
#./get
#cd
# seccomp
#cd
#sudo apt-get install -y ruby-dev -y
#sudo gem install seccomp-tools
