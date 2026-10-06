# syntax=docker/dockerfile:1.19
# Both image arguments must be resolved by digest before the build.
ARG K3S_IMAGE
ARG CUDA_IMAGE
FROM ${K3S_IMAGE} AS k3s
FROM ${CUDA_IMAGE}
ARG NVIDIA_CONTAINER_TOOLKIT_VERSION=1.20.1-1
USER root
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gnupg2 \
    && curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg \
    && curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' > /etc/apt/sources.list.d/nvidia-container-toolkit.list \
    && apt-get update && apt-get install -y --no-install-recommends \
       nvidia-container-toolkit=${NVIDIA_CONTAINER_TOOLKIT_VERSION} \
       nvidia-container-toolkit-base=${NVIDIA_CONTAINER_TOOLKIT_VERSION} \
       libnvidia-container-tools=${NVIDIA_CONTAINER_TOOLKIT_VERSION} \
       libnvidia-container1=${NVIDIA_CONTAINER_TOOLKIT_VERSION} \
    && dpkg-query -W > /installed-packages.txt \
    && rm -rf /var/lib/apt/lists/*
# Follow k3d's glibc CUDA node layout. Ubuntu uses merged /usr paths; copy
# directory contents to those concrete paths instead of replacing symlinks.
# K3s detects /usr/bin/nvidia-container-runtime at startup.
# Do not install Linux NVIDIA kernel drivers inside WSL or this container.
COPY --from=k3s /bin/ /usr/bin/
COPY --from=k3s /lib/ /usr/lib/
COPY --from=k3s /etc/ /etc/
COPY --from=k3s /usr/ /usr/
COPY --from=k3s /var/lib/ /var/lib/
VOLUME /var/lib/kubelet
VOLUME /var/lib/rancher/k3s
VOLUME /var/lib/cni
VOLUME /var/log
ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/var/lib/rancher/k3s/data/cni:/bin/aux"
ENV CRI_CONFIG_FILE="/var/lib/rancher/k3s/agent/etc/crictl.yaml"
ENV NVIDIA_VISIBLE_DEVICES=all NVIDIA_DRIVER_CAPABILITIES=compute,utility
ENTRYPOINT ["/bin/k3s"]
CMD ["agent"]
