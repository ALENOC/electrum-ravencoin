FROM debian:bullseye@sha256:43ef0c6c3585d5b406caa7a0f232ff5a19c1402aeb415f68bcd1cf9d10180af8

ENV LC_ALL=C.UTF-8 LANG=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive

# Debian Bullseye left regular security support, and deb.debian.org no longer
# serves the package versions its indexes reference, so apt-get install fails
# with a wall of 404s. Debian's archive mirror is immutable and self consistent,
# which is what a reproducible build image wants anyway.
RUN printf '%s\n' \
        'deb http://archive.debian.org/debian bullseye main' \
        > /etc/apt/sources.list && \
    printf '%s\n' \
        'Acquire::Check-Valid-Until "false";' \
        > /etc/apt/apt.conf.d/99electrum-archive && \
    apt-get update -q && \
    apt-get install -qy \
        git \
        gettext \
        python3 \
        python3-pip \
        python3-setuptools \
        python3-venv \
        faketime \
        && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean

# create new user to avoid using root; but with sudo access and no password for convenience.
ARG UID=1000
ENV USER="user"
ENV HOME_DIR="/home/${USER}"
ENV WORK_DIR="${HOME_DIR}/wspace" \
    PATH="${HOME_DIR}/.local/bin:${PATH}"
RUN useradd --uid $UID --create-home --shell /bin/bash ${USER}
RUN usermod -append --groups sudo ${USER}
RUN echo "%sudo ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
WORKDIR ${WORK_DIR}
RUN chown --recursive ${USER} ${WORK_DIR}
USER ${USER}
