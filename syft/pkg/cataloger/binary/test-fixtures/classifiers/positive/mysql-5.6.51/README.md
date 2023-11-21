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