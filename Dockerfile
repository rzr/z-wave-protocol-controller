# SPDX-License-Identifier: Zlib
# SPDX-FileCopyrightText: Silicon Laboratories Inc. https://www.silabs.com

FROM ubuntu:22.04 as builder

ENV DEBIAN_FRONTEND noninteractive
ENV LC_ALL en_US.UTF-8
ENV LANG ${LC_ALL}

ARG UNIFYSDK_GIT_REPOSITORY https://github.com/SiliconLabs/UnifySDK
ARG UNIFYSDK_GIT_TAG main

RUN echo "# log: Configuring locales" \
  && set -x  \
  && apt-get update -y \
  && apt-get install -y locales \
  && echo "${LC_ALL} UTF-8" | tee /etc/locale.gen \
  && locale-gen ${LC_ALL} \
  && dpkg-reconfigure locales \
  && TZ=Etc/UTC apt-get -y install tzdata \
  && date -u
  
ENV project z-wave-protocol-controller
ENV workdir /usr/local/opt/${project}
ADD . ${workdir}

WORKDIR ${workdir}

RUN echo "# log: Setup system" \
  && set -x  \
  && df -h \
  && apt-get update \
  && apt-get install -y --no-install-recommends -- make sudo \
  && ./helper.mk help setup \
  && date -u

RUN echo "# log: Build" \
  && set -x  \
  && ./helper.mk \
  && date -u \
  && echo "# log: Clean to only keep packages to save space" \
  && mkdir -p dist \
  && cd dist \
  && unzip ../build/dist/${project}*.zip \
  && cd - \
  && ./helper.mk distclean \
  && date -u

FROM ubuntu:22.04
ENV project z-wave-protocol-controller
ENV workdir /usr/local/opt/${project}
COPY --from=builder ${workdir}/dist/ ${workdir}/dist/
WORKDIR ${workdir}

RUN echo "# log: Install to system" \
  && set -x  \
  && apt-get update \
  && dpkg -i ./dist/${project}*/*.deb \
  || apt install -f -y --no-install-recommends \
  && echo "TODO: rm -rf dist # If artifacts are no more needed" \
  && apt-get clean -y \
  && rm -rf /var/lib/{apt,dpkg,cache,log}/ \
  && df -h \
  && date -u

ENTRYPOINT [ "/usr/bin/zpc" ]
CMD [ "--help" ]
