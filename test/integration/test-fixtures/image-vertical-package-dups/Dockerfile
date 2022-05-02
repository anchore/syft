FROM centos:7.9.2009
# modifying the RPM DB multiple times will result in duplicate packages when using all-layers (if there was no de-dup logic)
# curl is tricky, it already exists in the image and is being upgraded
RUN yum install -y wget curl
RUN yum install -y vsftpd
RUN yum install -y httpd