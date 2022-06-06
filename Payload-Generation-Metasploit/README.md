Metasploit Payload generation script with .DLL extension



## How to Install


1.  Run git clone ```https://github.com/subhajeet/Detect-Them-All/```
2.  Run cd ```Payload-Generation-Metasploit```
3.  Run ```sudo chmod a+x *```
4.  Inside the ```runall.sh``` change the ```/home/kali/exe``` to your desired folder where the generated payloads will be stored, this is important failing to do this will cause time loss and issues.
5.  Run ```sudo ./runall.sh```
6.  Enjoy your coffee.




## How do I change to new file extension?

- Just replace .dll with your favourite extension. 
- Run ```sudo apt install gedit```.
- Run ```sudo gedit 23.sh```
- Then you will go to the Find and replace option, just find ```.dll``` and replace it with ```.ps1```
- Save the file.
- COntinue this process for all the files.
- After completion run ```sudo ./runall.sh```
- Enjoy your day. 
