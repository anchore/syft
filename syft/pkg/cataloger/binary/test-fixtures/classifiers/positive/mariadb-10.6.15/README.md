The binary snippet was gathered with:

```bash
$ cat ./original-mariadb | strings | grep '-MariaDB'
# assert you can see the value


$ xxd ./original-mariadb | grep '\-MariaDB'
# get the address...


$ xxd -s 0x003dd5c0 -l 40 ./original-mariadb

003dd5c0: 2900 4c69 6e75 7800 3130 2e36 2e31 352d  ).Linux.10.6.15-
003dd5d0: 4d61 7269 6144 4200 7265 6164 6c69 6e65  MariaDB.readline
003dd5e0: 0078 3836 5f36 3400                      .x86_64.


$ dd if=./original-mariadb of=mariadb bs=1 skip=$((0x003dd5c0)) count=40

40+0 records in
40+0 records out
40 bytes transferred in 0.000264 secs (151515 bytes/sec)


$ xxd mariadb

00000000: 2900 4c69 6e75 7800 3130 2e36 2e31 352d  ).Linux.10.6.15-
00000010: 4d61 7269 6144 4200 7265 6164 6c69 6e65  MariaDB.readline
00000020: 0078 3836 5f36 3400                      .x86_64.
```