FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p build && cd build && \
    PYBIND11_DIR=$(python3 -c "import pybind11; print(pybind11.get_cmake_dir())") && \
    cmake .. -Dpybind11_DIR=$PYBIND11_DIR && \
    cmake --build .

EXPOSE 3000
# Added PYTHONPATH=/app/lib so Python finds scan.so inside lib/
CMD ["sh", "-c", "PYTHONPATH=/app/lib uvicorn lib.main:app --host 0.0.0.0 --port 3000"]