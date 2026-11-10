FROM python:3.12-slim
ENV PIP_DEFAULT_TIMEOUT=120 PIP_RETRIES=10 PIP_NO_CACHE_DIR=1
# CPU-only PyTorch in its own layer, so a retry does not repeat it once it succeeds
RUN pip install torch --index-url https://download.pytorch.org/whl/cpu
RUN pip install garak==0.17.1
WORKDIR /work
ENV XDG_DATA_HOME=/work/reports
ENTRYPOINT ["garak"]
