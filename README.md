Toolbox for pentesting.
The tool is written in Python and desgined
for penetration testing.



## Installation

Make sure you have installed Python, Git and Nmap in your environment.
Here you can get Python: https://www.python.org/downloads/
Here you can get Git: https://git-scm.com/downloads
Here you can get Nmap: https://nmap.org/download

Execute following commands in your Linux shell: 
1. git clone https://github.com/ariket/Toolbox.git
2. cd Toolbox
3. pip install -r requirements.txt

Now our tools is working in the current directory and every time you will try to run them then you need to go into the directory and run it, so eventually you will make a symbolic link so that you can access it from any directory you are in. 
4. sudo ln -sfv /Toolbox/crypto.py /usr/bin/crypto.py



Finally run 'python main.py' to start the toolbox main menu


## Usage

    crypto.py:
        ./files/text.txt

    scan.py:

    hashcrack.py:

    sshcrack.py:


## Contributing

See the Dev Environment Setup guide on GitHub, which will walk you through the whole process from installing all the dependencies, to cloning the repository, and finally to submitting a pull request. For slightly more information, see Contributing.

## Licensce

MIT
