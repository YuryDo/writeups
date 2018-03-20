**Description**

`Now that you have the user password from VM-SERVICES1 go and hunt the VM.`

**Files**
[vm.ova](https://drive.google.com/file/d/1269Xj-ZtRhr2qhV713V-XLYceD7OUYhA/view)


-----


**Solution**
Ok, in `VM-SERVICES1` we have already found the `ctf` user password - `infosec`.
Let's open the VM.
> Sincerely, already on solving `VM-SERVICES1` we've found all the clues and started to dig into our findings in the first task, but only after submitting the flag, we've found, that it was a 200 points flag for `VM-SERVICES2` =D

Now we can study all the `.bash_history` in users directories (`/root` & `/home/ctf`) and we'll find something very interesting:

-----


![](https://raw.githubusercontent.com/YuryDo/writeups/master/BackdoorCTF2018/Forensics/VM-SERVICES2/ctf_bash_history.png)


-----

Ok, there is a nasty keylogger service in the system.

-----

![](https://raw.githubusercontent.com/YuryDo/writeups/master/BackdoorCTF2018/Forensics/VM-SERVICES2/keylogger_service.png)


-----

Digging more, we'll find out:

/etc/systemd/system/keylogger.service - keylogger service location;

/usr/local/bin/[keylogger](https://github.com/YuryDo/writeups/blob/master/BackdoorCTF2018/Forensics/VM-SERVICES2/VM-files/keylogger) - keylogger binary location;

/var/spool/cron/[.kde](https://github.com/YuryDo/writeups/blob/master/BackdoorCTF2018/Forensics/VM-SERVICES2/VM-files/kde) - keyboard input log file;

/dev/input/event2 - the keyboard input, that's is logged by the keylogger;

The keyboard input log looks ugly and is encrypted. So, we have to deal with the binary file to find out the encryption method.
Ok, let's check strings:

-----


![](https://raw.githubusercontent.com/YuryDo/writeups/master/BackdoorCTF2018/Forensics/VM-SERVICES2/strings.png)


-----

No way, we won't find any plain clue and we'll reverse it, yay!
You don't have to dig too deep and you'll soon find an interesting function named `encrypt`:

-----


![](https://raw.githubusercontent.com/YuryDo/writeups/master/BackdoorCTF2018/Forensics/VM-SERVICES2/encrypt_func.png)


-----

`encypt` - is a stream cipher function. Python implementation:

```
for i in range(len(str)):
        randomNumber = rand();
        str[i] = (str[i] * str[i] + randomNumber) % 0x100;
        fputc(file, str[i]);
```

The result is the low byte from the `symbol being multiplied by itself + random number (pseudo random encryption key)`.

And the point is that the algorithm and the pseudo random key seed are hardcoded in the `keylogger`.

The algorithm is realised by the `rand` function, and the `seed` is set to `0`

-----


![](https://raw.githubusercontent.com/YuryDo/writeups/master/BackdoorCTF2018/Forensics/VM-SERVICES2/rand.png)


-----

As a result we can generate the same encryption key, that is used in the keylogger:

```
rand_key = [
    0x6b8b4567, 0x327b23c6, 0x643c9869, 0x66334873,
    0x74b0dc51, 0x19495cff, 0x2ae8944a, 0x625558ec,
    0x238e1f29, 0x46e87ccd, 0x3d1b58ba, 0x507ed7ab,
    0x2eb141f2, 0x41b71efb, 0x79e2a9e3, 0x7545e146,
    0x515f007c, 0x5bd062c2, 0x12200854, 0x4db127f8,
    0x0216231b, 0x1f16e9e8, 0x1190cde7, 0x66ef438d,
    0x140e0f76, 0x3352255a, 0x109cf92e, 0x0ded7263,
    0x7fdcc233, 0x1befd79f, 0x41a7c4c9, 0x6b68079a,
    0x4e6afb66, 0x25e45d32, 0x519b500d, 0x431bd7b7,
    0x3f2dba31, 0x7c83e458, 0x257130a3, 0x62bbd95a,
    0x436c6125, 0x628c895d, 0x333ab105, 0x721da317,
    0x2443a858, 0x2d1d5ae9, 0x6763845e, 0x75a2a8d4,
    0x08edbdab, 0x79838cb2, 0x4353d0cd, 0x0b03e0c6,
];
```

Multiplication of 1 byte integers, and discarding the high byte leads to information leakage, so we have the opportunity to brute our hash:

```
f = open('kde', 'rb');
data = f.read();
f.close()

d = bytearray(data);

rand_key = [...];


for i in range(len(rand_key)):
    r = rand_key[i];
    d = data[i];

    chrs = '';
    for j in range(20, 128):
        k = ((j * j + r) % 0x100);

        if k == d:
            chrs += chr(j)
    print(chrs)
```

Before running the script we have deleted `"=====\r\n` in `.kde` log file.

Getting rid of unreadable chars we had the result:

```
1.   =C
2.   ,4LTlt
3.   :Fz
4.   {
5.   c
6.   0@P`p
7.   .Rn
8.   6Jv
9.   2Nr
10.  ,4LTlt
11.	 7I
12.	 :Fz
13.	 :Fz
14.	 !_
15.	 y
16.	 0@P`p
17.	 u
18.	 !_
19.	 (8HXhx
20.	 ,4LTlt
21.	 6Jv
22.	 3M
23.	 !_
24.	 &Zf
25.	 0@P`p
26.	 u
27.	 .Rn
28.	 $<D\d|
29.	 !_
30.	 0@P`p
31.	 u
32.	 2Nr
33.	 !_
34.	 (8HXhx
35.	 1O
36.	 $<D\d|
37.	 $<D\d|
38.	 3M
39.	 .Rn
40.	 !_
41.	 5K
42.	 3M
43.	 2Nr
44.	 6Jv
45.	 1O
46.	 c
47.	 3M
48.	 }
```

So, it turned out into a guessing game. We had to choose the right character for every position. It was easy to see CTF{}. But then we had to spend about 30 minutes to solve the rebus =D

`CTF{c0n6r47zz_y0u_h4v3_f0und_0ur_h1dd3n_53rv1c3}`

> We had some problems with submitting the flag, because when we were retyping the result we misstyped a cyrillic symbol in it and got the wrong SHA256 hash. But thx to the orgs, we've found it out.

It cost us plenty of time to solve this task, but it was definitely interesting and fun.

P.S. Thx to the authors of the task, that the keylogger didn't store its log in CRC32 previously XORed with few rounds ;)

**That's All Folks!**
