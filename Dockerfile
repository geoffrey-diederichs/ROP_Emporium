from debian:latest

# Updates and install what's necessary
RUN apt update && apt upgrade -y
RUN apt install -y procps file curl gdb python3 pip python3-pwntools qemu-user qemu-user-static gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu binutils-aarch64-linux-gnu-dbg build-essential gcc-arm-linux-gnueabihf binutils-arm-linux-gnueabihf binutils-arm-linux-gnueabihf-dbg gdb-multiarch qemu-user gcc-arm-linux-gnueabi libc6-mipsel-cross
RUN apt autoremove -y && apt clean

# Setting up libs at the right paths
RUN mkdir -p /lib/arm-linux-gnueabi/
RUN cp -r /usr/arm-linux-gnueabi/lib/* /lib/arm-linux-gnueabi/
RUN ln -s /lib/arm-linux-gnueabi/ld-linux.so.3 /lib/
RUN mkdir -p /lib/mipsel-linux-gnu/
RUN cp -r /usr/mipsel-linux-gnu/lib/* /lib/mipsel-linux-gnu/
RUN ln -s /usr/mipsel-linux-gnu/lib/ld.so.1 /lib/

# Installing GEF for GDB
RUN /bin/bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
RUN echo "export LC_CTYPE=C.UTF-8" >> /root/.bashrc

CMD ["/bin/bash"]
