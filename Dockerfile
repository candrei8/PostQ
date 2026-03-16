FROM python:3.12-slim AS builder
WORKDIR /build
COPY pyproject.toml uv.lock ./
COPY src/ src/
RUN pip install --no-cache-dir hatch && hatch build

FROM python:3.12-slim
LABEL maintainer="EYD Company <info@eyd.com>"
LABEL description="quant-scan — Post-Quantum Cryptography Vulnerability Scanner"

RUN groupadd -r quant && useradd -r -g quant quant
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

USER quant
WORKDIR /scan
ENTRYPOINT ["quant-scan"]
CMD ["scan", ".", "--format", "json"]
