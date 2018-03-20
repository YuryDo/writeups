**Dscription**

`You are a given a VM image vm.ova. The flag is CTF{password}.`

**Files**
[vm.ova](https://drive.google.com/file/d/1269Xj-ZtRhr2qhV713V-XLYceD7OUYhA/view)


-----


**Solution**
So, we have an Ubuntu 17.04 VM image.
Let's open it in a hypervisor you prefer more.
First of all we have to get into the boot menu (pres ESC on load) and boot in recovery mode.
And you are root. 
We can study all the `.bash_history` in users directories (`/root` & `/home/ctf`) and we'll find something very interesting. But... It's an easy task, right?
Ok, let's see /etc/shadow contents, and we'll find out, that only the ctf password is set.

-----


![](https://raw.githubusercontent.com/YuryDo/writeups/master/BackdoorCTF2018/Forensics/VM-SERVICES1/shadow.png)


-----


That easy? Yeah, it's a 75 points task. Now you can go and brute it using `rockyou` as dictionary.
The password will be `infosec`. So now you have only submit the SHA256 of the flag:

`b83778882e48e092c3d722aa4e4e705f4b23ce396c461d889bc53ef0a4c87a37`


**That's All Folks!**
