# TG Proxy

## Windows

**[Скачать TG-Proxy.exe](https://github.com/Ahatina01/tg-proxy-list/raw/refs/heads/main/downloads/TG-Proxy.exe)** — переносимый файл для Windows 10/11 с .NET Framework 4.8.

[Исходники Windows](windows) · [Архив проекта](downloads/TG-Proxy-Windows-project.zip) · [Проверка Windows](docs/windows-verification.txt)

EXE собран и запущен, 23 проверки пройдены, открытие окна подтверждения прокси в Telegram Desktop проверено. Файл без Authenticode-сертификата издателя. Используется зарегистрированный обработчик `tg://`.

SHA-256 EXE: `0DD7EE5F2A61C70ABBEAD220C521B58BBAD9D40E68DC0C5D18F41C5D8EA3EC98`.

## Android

Простое Android-приложение для выбора прокси Telegram. Android 8.0 и новее.

## Скачать

**[Скачать TG-Proxy.apk](https://github.com/Ahatina01/tg-proxy-list/raw/refs/heads/main/downloads/TG-Proxy.apk)**

[Архив Android-проекта](downloads/TG-Proxy-project.zip) · [Исходники и сборка](android) · [Отчёт о проверке](docs/verification.txt)

APK подписан. SHA-256: `C167FABAEA7E3A516D4D54CCA261F7200C563576290D438861F1DF3DC2B5B0D6`.

## Использование

Установите APK, откройте TG Proxy и нажмите «Подключить». Приложение скачает список, проверит MTProto-прокси параллельно и откроет официальный Telegram с выбранной ссылкой. Подтвердите подключение в Telegram, если он попросит.

Список обновляется здесь: [proxies.txt](proxies.txt). После редактирования пересобирать приложение не нужно: при следующем нажатии выполняется новый запрос. При ошибке загрузки используются кэш и встроенный резерв.

WEB Proxy пропускаются. Проверка использует Fake TLS и MTProto req_pq/resPQ, а не только открытый TCP-порт. Приложение не может автоматически переключать уже подключённый Telegram.

## Проверено

Release-сборка успешна, подпись APK проверена, 9 JUnit-тестов прошли. В сетевой проверке 4 из 6 MTProto-прокси ответили корректно. Android Lint: 0 ошибок. Установка и открытие Telegram на реальном Android-устройстве в среде сборки не проверены.

Приватный ключ подписи в этот репозиторий не включён.
