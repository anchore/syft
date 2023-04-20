FROM busybox:1.28.1@sha256:c7b0a24019b0e6eda714ec0fa137ad42bc44a754d9cea17d14fba3a80ccc1ee4

ADD file-1.txt .
RUN chmod 644 file-1.txt
RUN chown 1:2 file-1.txt
RUN ln -s file-1.txt symlink-1
# note: hard links may behave inconsistently, this should be a golden image
RUN ln file-1.txt hardlink-1
RUN mknod char-device-1 c 89 1
RUN mknod block-device-1 b 0 1
RUN mknod fifo-1 p
RUN mkdir /dir
RUN rm -rf home etc/group etc/localtime etc/mtab etc/network etc/passwd etc/shadow var usr bin/*