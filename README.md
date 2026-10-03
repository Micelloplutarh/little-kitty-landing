# little-kitty landing

Статический link-in-bio лендинг для деплоя через Coolify.

## Состав

- `index.html` — страница целиком (вёрстка и стили внутри). Контент — имя,
  слоган, сообщение, ссылка CTA, картинки — правится в блоке `CONFIG` внизу файла.
- `img/` — `bg.jpg` (фон), `avatar.jpg` (аватар в плашке). `IMG_0849.JPG`
  в коде не используется.
- `Dockerfile` + `nginx.conf` — контейнер nginx: статика, кэш для картинок и
  JS/CSS, порт 80.

## Деплой в Coolify

1. VPS с установленным Coolify должен быть онлайн (панель обычно на порту 8000).
2. В DNS домена прописать A-запись на IP VPS. Обратный прокси и HTTPS
   (Let's Encrypt) Coolify поднимает сам.
3. Coolify → Projects → **+ New** → **Public Repository** → вставить адрес
   этого репозитория на GitHub.
4. Build Pack: **Dockerfile**. Base Directory: `/` (Dockerfile в корне репозитория).
5. **Domains:** указать FQDN домена (например `kitty.example.com`).
6. **Deploy.** Проверка: `curl -I https://<домен>` отдаёт 200, страница открывается.

Новый лендинг = клон этого репозитория + свои значения в `CONFIG` + свои картинки
в `img/`.

Обновлено: 2026-10-03
