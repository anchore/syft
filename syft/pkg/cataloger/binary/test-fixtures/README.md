## Evidence details for `binary` cataloger content matching

### `original-mariadb`
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

### `original-mysql 5.6.51`
The binary snippet was gathered with:

```bash
$ cat ./original-mysql | strings | grep '5.6.51'
# assert you can see the value


$ xxd ./original-mysql | grep '5.6.51'
# get the address...


$ xxd -s 0x008f13d0 -l 100 original-mysql

008f13d0: 2d62 6163 6b75 702d 7265 7374 6f72 6572  -backup-restorer
008f13e0: 2d6d 7973 716c 2d35 2e36 2f6d 7973 716c  -mysql-5.6/mysql
008f13f0: 2d35 2e36 2e35 312f 636c 6965 6e74 2f63  -5.6.51/client/c
008f1400: 6f6d 706c 6574 696f 6e5f 6861 7368 2e63  ompletion_hash.c
008f1410: 6300 2f76 6172 2f76 6361 702f 6461 7461  c./var/vcap/data
008f1420: 2f63 6f6d 7069 6c65 2f64 6174 6162 6173  /compile/databas
008f1430: 652d 6261                                e-ba


$ dd if=./original-mysql of=mysql bs=1 skip=$((0x008f13d0)) count=100

100+0 records in
100+0 records out
100 bytes transferred in 0.000642 secs (155763 bytes/sec)


$ xxd mysql
                   
00000000: 2d62 6163 6b75 702d 7265 7374 6f72 6572  -backup-restorer
00000010: 2d6d 7973 716c 2d35 2e36 2f6d 7973 716c  -mysql-5.6/mysql
00000020: 2d35 2e36 2e35 312f 636c 6965 6e74 2f63  -5.6.51/client/c
00000030: 6f6d 706c 6574 696f 6e5f 6861 7368 2e63  ompletion_hash.c
00000040: 6300 2f76 6172 2f76 6361 702f 6461 7461  c./var/vcap/data
00000050: 2f63 6f6d 7069 6c65 2f64 6174 6162 6173  /compile/databas
00000060: 652d 6261                                e-ba
```


### `original-mysql-8`
The binary snippet was gathered with:
```bash
$ cat ./original-mysql | strings | grep '8.0.34'
# assert you can see the value


$ xxd ./original-mysql | grep '8.0.34'
# get the address...


$ xxd -s 0x0014cd20 -l 100 original-mysql

0014cd20: 2069 7320 616c 7265 6164 7920 6c6f 6164   is already load
0014cd30: 6564 0000 0000 0000 2e2e 2f2e 2e2f 6d79  ed......../../my
0014cd40: 7371 6c2d 382e 302e 3334 2f73 716c 2d63  sql-8.0.34/sql-c
0014cd50: 6f6d 6d6f 6e2f 636c 6965 6e74 5f70 6c75  ommon/client_plu
0014cd60: 6769 6e2e 6363 002f 7573 722f 6c6f 6361  gin.cc./usr/loca
0014cd70: 6c2f 6d79 7371 6c2f 6c69 622f 706c 7567  l/mysql/lib/plug
0014cd80: 696e 0049                                in.I



$ dd if=./original-mysql of=mysql bs=1 skip=$((0x0014cd20)) count=100

100+0 records in
100+0 records out
100 bytes transferred in 0.000519 secs (192678 bytes/sec)


$  xxd mysql            
                  
00000000: 2069 7320 616c 7265 6164 7920 6c6f 6164   is already load
00000010: 6564 0000 0000 0000 2e2e 2f2e 2e2f 6d79  ed......../../my
00000020: 7371 6c2d 382e 302e 3334 2f73 716c 2d63  sql-8.0.34/sql-c
00000030: 6f6d 6d6f 6e2f 636c 6965 6e74 5f70 6c75  ommon/client_plu
00000040: 6769 6e2e 6363 002f 7573 722f 6c6f 6361  gin.cc./usr/loca
00000050: 6c2f 6d79 7371 6c2f 6c69 622f 706c 7567  l/mysql/lib/plug
00000060: 696e 0049                                in.I
```