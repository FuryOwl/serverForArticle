# Указываем базовый образ
FROM ubuntu

# Устанавливаем зависимости
RUN apt-get update && apt-get install -y cmake git g++

# Создаем директорию /app
RUN mkdir /app
WORKDIR /app
RUN git clone https://github.com/FuryOwl/base64server
WORKDIR /app/base64server
RUN mkdir build
WORKDIR /app/base64server/build

# CMake
RUN cmake ..
RUN make

# Определяем точку входа
ENTRYPOINT ["/app/base64server/build/base64server"]

# Пробрасываем порт 80 внутри контейнера на порт 8080 хоста
EXPOSE 80
