# Imagen base oficial de Python
FROM python:3.11-slim

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copiar requirements y luego instalar dependencias
COPY requirements.txt .

# Instalar dependencias
RUN apt-get update && \
    apt-get install -y nmap dnsutils && \
    pip install --no-cache-dir -r requirements.txt

# Copiar el resto del proyecto
COPY . .

# Variables de entorno
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Comando por defecto (puedes cambiarlo si quieres otro archivo como punto de entrada)
CMD ["python", "main.py"]
