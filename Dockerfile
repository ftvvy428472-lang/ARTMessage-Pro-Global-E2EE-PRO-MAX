# ARTMessage backend — Dockerfile для деплоя на Render

FROM python:3.10-slim

# Отключаем буферизацию вывода Python и создание .pyc файлов
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Системные зависимости, нужные для сборки bcrypt/cryptography
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc build-essential \
    && rm -rf /var/lib/apt/lists/*

# Сначала копируем только requirements.txt, чтобы использовать кэш Docker-слоёв
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Копируем остальной код приложения
COPY . .

# Директории для базы данных и загруженных файлов (создаются и в рантайме,
# но заранее создаём их, чтобы права были корректными)
RUN mkdir -p /app/uploads/temp /app/uploads/avatars

# Render передаёт номер порта через переменную окружения PORT
ENV PORT=8000
EXPOSE 8000

# Запуск сервера. Render подставит свой $PORT автоматически.
CMD ["sh", "-c", "uvicorn server:app --host 0.0.0.0 --port ${PORT}"]
