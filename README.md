Toolbox for pentesting.

Make sure you have installed Python, Git and Nmap in your environment.
Here you can get Python: https://www.python.org/downloads/
Here you can get Git: https://git-scm.com/downloads
Here you can get Nmap: https://nmap.org/download

Execute following commands in your Linux shell: 
1. git clone https://github.com/ariket/Toolbox.git
2. cd Toolbox
3. pip install -r requirements.txt


Now our tool is working in the current directory and every time we will try to run it then we need to go into the directory and run it, so now we will make a symbolic link so that we can access it from any directory we are in. 
4. sudo ln -sfv /opt/Sublist3r/sublist3r.py /usr/bin/sublist3r



Finally run 'python main.py' to start the toolbox main menu
