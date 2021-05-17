# Passwd
sudo passwd
# update
sudo apt update
sudo apt install vim gdb wget git curl nmap zsh python-pip -y
# remove useless software
sudo apt remove libreoffice-common unity-webapps-common thunderbird totem rhythmbox simple-scan gnome-mahjongg aisleriot gnome-mines cheese transmission-common gnome-orca webbrowser-app deja-dup
sudo apt autoremove
# install ipython
sudo apt-get install ipython
# install pwntools
sudo apt-get install python2.7 python-pip python-dev git libssl-dev libffi-dev build-essential
sudo pip install --upgrade pwntools
# install angr
#sudo apt-get install python-dev libffi-dev build-essential
#sudo pip install angr
# install zsh   
sudo apt-get install zsh
sudo apt-get install git
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
chsh -s /usr/bin/zsh


# sudo apt-get install gcc-multilib
# sudo apt-get install qemu
# install peda
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
# pwngdb
cd ~/
git clone https://github.com/scwuaptx/Pwngdb.git
cp ~/Pwngdb/.gdbinit ~/
# install pwndbg
#git clone https://github.com/pwndbg/pwndbg
#cd pwndbg
#./setup.sh
# install one_gadget
sudo apt install ruby -y
sudo apt install gem -y
sudo gem install one_gadget
# install libc-database
#git clone https://github.com/niklasb/libc-database
sudo apt install -y ruby-dev
sudo gem install seccomp-tools
