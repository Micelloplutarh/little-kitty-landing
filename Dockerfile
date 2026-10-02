FROM nginx:1.27-alpine

# Статика целиком в корень раздачи nginx
COPY . /usr/share/nginx/html

# Кастомный конфиг: кэш для static-ассетов
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
