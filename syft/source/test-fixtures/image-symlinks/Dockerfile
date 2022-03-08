# LAYER 0:
FROM busybox:latest

# LAYER 1:
ADD file-1.txt .

# LAYER 2: link with previous data
RUN ln -s ./file-1.txt link-1

# LAYER 3: link with future data
RUN ln -s ./file-2.txt link-2
# LAYER 4:
ADD file-2.txt .

# LAYER 5: link with current data
RUN echo "file 3" > file-3.txt && ln -s ./file-3.txt link-within

# LAYER 6: multiple links (link-indirect > link-2 > file-2.txt)
RUN ln -s ./link-2 link-indirect

# LAYER 7: override contents / resolution
ADD new-file-2.txt file-2.txt

# LAYER 8: dead link
RUN ln -s ./i-dont-exist.txt link-dead

# LAYER 9: add the parent dir
ADD parent /parent

# LAYER 10: parent is a symlink
RUN ln -s /parent parent-link

# LAYER 11: parent is a symlink and the child target is overridden
COPY new-file-4.txt /parent-link/file-4.txt