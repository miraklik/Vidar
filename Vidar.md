# Vidar

| Malware Name | File Type | SHA256 |
| --- | ----------- | ----------- |
| Vidar | x64 exe | d08b7a755e3606050156cd2834e588c02f1c945b6ee3ee7b567f70dd24b10c92 |

## Обзор

**Vidar** - это info-stealer, впервые обнаруженный в конце 2018 года. Он является форком более старого стилера **Arkei** и продаётся по модели Malware-as-a-Service (MaaS).

Основная задача malware — кража чувствительных данных с заражённого компьютера:
- Учётные данные и cookies из браузеров
- Данные криптовалютных кошельков
- История браузера, autofill, банковские карты
- Данные мессенджеров (Telegram и др.)
- Скриншоты экрана
- Определённые файлы по заданным маскам

Помимо кражи данных, Vidar иногда используется как initial access tool: украденные логи продаются на теневых рынках, после чего другие группировки могут использовать их для дальнейшего заражения (в том числе ransomware).

## Процесс анализа

### 1. Определение типа файла

Сначала я проверил тип файла с помощью утилиты `file`:

Результат PE32+ executable (GUI) x86-64, for MS Windows

<img src="/screenshots/file.png" width=80% height=80%>

Теперь мы знаем, что файл у нас с расширением .exe 

### 2. Анализ в Detect It Easy (DiE)

Далее я загрузил образец в `Detect It Easy (DiE)`:

<img src="/screenshots/DiE.png" width=80% height=80%>

**Важные наблюдения:**

Файл написан на Go (версия компилятора go1.23.9).
Размер файла очень большой (87.31 МБ). Для обычного Go-бинарника это нетипично и почти наверняка указывает на использование техники file inflation

### 3. Overlay и File Inflation

Одной из самых заметных особенностей этого образца является наличие очень большого **Оверлей**.

Согласно Detect It Easy:
- **Offset:** `0x0054e000`
- **Size:** `0x05201fa8` (~82 МБ)

Это означает, что основная часть файла (примерно 94% от общего размера 87.31 МБ) находится **за пределами** настоящей PE-структуры и является Overlay.

В контексте вредоносов такой большой Оверлей почти всегда используется для техники **File Inflation** - искусственного раздувания размера файла путём добавления большого количества null-байтов или мусорных данных. Это делается для того, чтобы:

- Обойти некоторые антивирусы и песочницы, у которых есть ограничение на максимальный размер анализируемого файла
- Усложнить автоматический анализ

### 4. Очистка файла от Overlay

Для продолжения анализа Overlay был удалён с помощью простого Python-скрипта:

```
with open("d08b7a755e3606050156cd2834e588c02f1c945b6ee3ee7b567f70dd24b10c92.exe", "rb") as f:
    data = f.read()

# Overlay начинается с 0x54e000
clean_pe = data[:0x54e000]

with open("vidar_clean.exe", "wb") as f:
    f.write(clean_pe)

print(f"Чистый PE сохранён, размер: {len(clean_pe)} байт")
```

Теперь когда мы отбросили Оверлей посмотрим стал ли размер файла нормальным.
Снова закинем его в `Detect it Easy (DiE)`:

<img src="/screenshots/DiE_clean.png" width=80% height=80%>

Как мы видим размер файла стал **5.30 МБ** 

### 5. Статический анализ строк

Теперь давайте найдем строки в чистом PE-файле используем для этого утилиты `strings`:

```bash
strings vidar_clean.exe > strings_clean.txt
```

Теперь попробуем что нибудь найти с фильтром интересных строк:

```bash 
strings vidar_clean.exe | findstr /i "wallet crypto telegram steam chrome firefox cookie login mutex http https t.me password browser" > interesting_strings.txt
```

<img src="/screenshots/strings_intersting.png" width=80% height=80%>

**Интересные находки:**

password, Password, passwordSet
Avalanche Risk Analysis System
https://avalanche.example.com/data?region=
https://avalanche.example.com/api?station=Alpine&date=2024-01-15
Hex encoded 'avalanche': %s

## Анализ в ANY.RUN

<img src="/screenshots/any.run.png" width=80% height=80%>

Мы можем заметить сетевую активность нашего вредоноса **vidar_clean.exe**:
 - Подключился к IP 46.62.133[.]5:443
 - Провайдер: Hetzner Online GmbH (Германия)
 - Объём трафика: ↑ 7 KB / ↓ 17 KB
 - Any.Run также зафиксировал, что процесс проверяет, запущен ли он в виртуальной среде (anti-VM/anti-sandbox).

<img src="/screenshots/detect_vm.png" width=80% height=80%>


<img src="/screenshots/virus_total.png" width=80% height=80%>

Репутация IP 46.62.133[.]5:
 - 12 из 90 вендоров считают его вредоносным
 - Community Score: -11
 - Помечается как Malware / Criminal IP / Malicious

### Сетевая активность

Также, При запуске в Any.Run образец установил HTTPS-соединение с IP-адресом `46.62.133.5` (Hetzner, Германия) и выполнил несколько POST-запросов:

| Время     | Метод | URL                      | Статус | Размер ответа |
|-----------|-------|--------------------------|--------|---------------|
| 1226 ms   | POST  | https://46.62.133.5/     | 200 OK | 344 B         |
| 1404 ms   | POST  | https://46.62.133.5/     | 200 OK | 4 KB          |
| 1668 ms   | POST  | https://46.62.133.5/     | 200 OK | 7 KB          |
| 1926 ms   | POST  | https://46.62.133.5/     | 200 OK | 608 B         |

Взглянув внутрь этих POST-запросов я увидел строчку зашифрованную в Base64: 

```bash
eyJhenVyZSI6MSwiZGVidWciOjEsInN0ZWFtIjoxLCJhbnRpdm0iOjEsImxvYWRlciI6MSwiQ29va2llcyI6MSwiSGlzdG9yeSI6MSwicmVxdWVzdCI6ImlkX3JlcXVlc3QiLCJ0ZWxlZ3JhbSI6MSwic2NyZWVuc2hvdCI6MCwic2hlbGxfY29kZSI6MCwidGhyZWFkX2NvdW50IjowLCJzdGVhbF9kaXNjb3JkIjoxLCJ6aXBfdGhyZXNob2xkIjoxLCJjcnlwdG9jdXJyZW5jeSI6MSwiZ3JhYmJlcl9zaXplX21heCI6MjA0OCwidG9rZW4iOjUwOTI2MDUwfQ==
```

<img src="/screenshots/post-request.png" width=80% height=80%>

### Расшифровка C2-конфигурации

Расшифровав ее в **CyberChef** можно увидеть данные которые наш вредонос посылал своего C2 серверу

<img src="/screenshots/post_c2.png" width=80% height=80%>

<img src="/screenshots/post_c2_2.png" width=80% height=80%>

```json
{
  "azure": 1,
  "debug": 1,
  "steam": 1,
  "antivm": 1,
  "loader": 1,
  "Cookies": 1,
  "History": 1,
  "request": "id_request",
  "telegram": 1,
  "screenshot": 0,
  "shell_code": 0,
  "thread_count": 0,
  "steal_discord": 1,
  "zip_threshold": 1,
  "cryptocurrency": 1,
  "grabber_size_max": 2048,
  "token": 50926050
}
```

Также были получены правила сбора файлов (grabber):

**Desktop:**
```
*wallet*, *seed*, *btc*, *key*, *2fa*, *crypto*, *coin*, *private*, *auth*, *ledger*, *trezor*, *pass*, *recovery*, *.txt, *.jpg, *.png
```

**Flash Drive (съёмные носители):**
```
*wallet*, *seed*, *recovery*, *.txt
```

Это подтверждает, что образец является info-stealer’ом с активными модулями:
- Кража cookies и истории браузеров
- Кража данных Steam
- Кража данных Telegram
- Кража данных Discord
- Кража криптовалютных кошельков и связанных файлов
- Anti-VM проверки

---

## Индикаторы компрометации (IOC)

| Тип              | Значение                                                           |
|------------------|--------------------------------------------------------------------|
| SHA256           | `d08b7a755e3606050156cd2834e588c02f1c945b6ee3ee7b567f70dd24b10c92` |
| C2 IP            | `46.62.133.5`                                                      |
| C2 Port          | `443`                                                              |
| Провайдер C2     | Hetzner Online GmbH (Германия)                                     |
| Протокол         | HTTPS (POST)                                                       |

---

## MITRE ATT&CK Mapping

| Тактика                  | Техника                                      | ID          |
|--------------------------|----------------------------------------------|-------------|
| Defense Evasion          | Virtualization/Sandbox Evasion               | T1497       |
| Defense Evasion          | Obfuscated Files or Information              | T1027       |
| Command and Control      | Application Layer Protocol: Web Protocols    | T1071.001   |
| Collection               | Data from Local System                       | T1005       |
| Collection               | Data from Removable Media                    | T1025       |
| Credential Access        | Credentials from Web Browsers                | T1555.003   |
| Credential Access        | Steal Application Access Token               | T1528       |

---