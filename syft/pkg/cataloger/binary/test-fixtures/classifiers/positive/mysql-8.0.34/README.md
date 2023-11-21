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