# Практическая работа № 12. Усиление SSH

**Дисциплина:** Операционные системы. **Специальность:** 10.05.01 «Компьютерная безопасность», университет, 3-й курс. **Продолжительность:** 90 минут; установка пакетов и снимки выполняются заранее. **Варианты:** 27, номер соответствует номеру студента по списку в журнале.

Тема взята из раздела 4.2 РПД: отключение небезопасных параметров, ограничение пользователей и способов входа, настройка ключевой аутентификации, проверка допустимых и отклонённых подключений из Kali Linux. Работа опирается на темы об аутентификации, разграничении доступа и службах; доверие к ключам узла связано с темой 12 о цепочке доверия.

**Вариант для предоставленного «Орла» 2.12.22:** Astra Linux Common Edition «Орёл» 2.12.22, штатный OpenSSH-сервер из ISO: в ПР6 зафиксирован пакет openssh-server 7.4p1-10+deb9u6astra6. Клиент — OpenSSH на Kali из стенда ПР1. Параметры конфигурации подобраны так, чтобы их поддерживал OpenSSH 7.4: например, используется ChallengeResponseAuthentication, а не появившееся позже имя KbdInteractiveAuthentication. Изменяется **настоящая** конфигурация `/etc/ssh/sshd_config`: с резервной копией, проверкой синтаксиса до применения, открытой локальной консолью и восстановлением в конце.

**Граница результата:** работа проверяет собственную Astra с собственной Kali. Пароли вводятся только интерактивно и только при доставке ключа; подбора паролей, Hydra, sshpass и скриптов NSE категорий brute/intrusive нет. Контрольные подключения выполняются в режиме BatchMode: клиент не запрашивает пароль, каждая проверка — одно подключение. Закрытый ключ, его парольная фраза и пароли учётных записей в отчёт не включаются.

## Содержание

1. [Цель и результаты](#goal)
2. [Стенд и предварительная подготовка](#prepare)
3. [Теория: что усиливается и как это проверить](#theory)
4. [Индивидуальное задание](#variant)
5. [Ход выполнения](#steps)
6. [Результаты и отчёт](#report)
7. [Контрольные вопросы и оценивание](#assessment)
8. [Диагностика и источники](#sources)

<a id="goal"></a>
## 1. Цель и результаты

Цель — перевести SSH-сервер с настроек по умолчанию на ключевую аутентификацию для ограниченного круга пользователей, отключить небезопасные возможности и доказать результат двумя независимыми способами: эффективной конфигурацией сервера и матрицей контрольных подключений с Kali, подтверждённой журналом.

Задачи:
- зафиксировать версии, исходную конфигурацию и её хеш, создать резервную копию;
- создать две учебные записи и группу, сгенерировать на Kali ключ с парольной фразой, проверить ключ узла и доставить открытый ключ;
- снять исходную матрицу подключений и список алгоритмов сервера;
- составить блок усиления по варианту, собрать конфигурацию-кандидат, проверить её `sshd -t` и `sshd -T`, проверить требования скриптом;
- применить конфигурацию без потери управления и повторить проверки;
- сопоставить результаты с журналом сервера, восстановить исходную конфигурацию и удалить учебные объекты.

Результат — эффективные конфигурации для двух пользователей, отчёты аудита, три матрицы подключений (до, после, после восстановления), два списка алгоритмов, сводки журнала, таблица tests.csv и подтверждение очистки. Не объявляйте вход запрещённым по одному только тексту конфигурации: запрет подтверждается фактической попыткой и журналом.

<a id="prepare"></a>
## 2. Стенд и предварительная подготовка

Используйте [паспорт ПР1](reference/Lab1.md). В гипервизоре обе VM имеют единственный адаптер Internal Network `oslab-vNN`; Astra — `10.50.V.10/24`, Kali — `10.50.V.20/24`, шлюз/DNS пустые, default route отсутствует в IPv4 и IPv6. Иной ранее утверждённый паспорт имеет приоритет; фактические параметры фиксируются в отчёте.

Таблица 1 — Необходимые средства

| Машина | Пакеты / команды | Назначение |
|---|---|---|
| Astra | openssh-server (`/usr/sbin/sshd`), openssh-client (`ssh-keygen`) | Сервер, проверка конфигурации, отпечаток ключа узла |
| Astra | systemd, journalctl, sudo, passwd, useradd/groupadd/userdel | Служба ssh, журнал, учебные записи |
| Astra | python3, coreutils (sha256sum, install), diffutils | Скрипт комплекта, хеши, сравнение конфигураций |
| Kali | openssh-client (ssh, ssh-keygen, ssh-keyscan, ssh-copy-id, ssh-agent) | Ключ, проверка ключа узла, доставка ключа, контрольные подключения |
| Kali | nmap, python3 | Список алгоритмов сервера, матрица подключений |

Таблица 2 — Состав комплекта

| Путь | Назначение |
|---|---|
| [tools/pr12.py](tools/pr12.py) | Astra: сессия, аудит эффективной конфигурации, сводка журнала, таблица тестов, проверка очистки |
| [tools/pr12_probe.py](tools/pr12_probe.py) | Kali: семь контрольных подключений к своей Astra с ожидаемыми результатами |
| SHA256SUMS.txt | Контрольные суммы комплекта |

Скопируйте каталог комплекта целиком в `$HOME/pr12/kit` на Astra и на Kali через разрешённый носитель или средство гипервизора. Скрипты используют только стандартную библиотеку Python 3.5.

### 2.1. Проверка программ и комплекта

На Astra, обычная учебная запись:

```bash
cat /etc/os-release
cat /etc/astra_version 2>/dev/null
dpkg-query -W openssh-server openssh-client
ssh -V
sudo /usr/sbin/sshd -t && echo SSHD_CONFIG_OK
systemctl is-active ssh
ls -l /etc/ssh/ssh_host_*_key.pub
cd "$HOME/pr12/kit" && sha256sum -c SHA256SUMS.txt | grep -v ': OK$'; cd "$HOME/pr12" || exit
```

На Kali:

```bash
ssh -V
nmap --version | head -n 1
python3 --version
for c in ssh ssh-keygen ssh-keyscan ssh-copy-id ssh-agent ssh-add nmap; do command -v "$c" || printf 'ОТСУТСТВУЕТ: %s\n' "$c"; done
cd "$HOME/pr12/kit" && sha256sum -c SHA256SUMS.txt | grep -v ': OK$'; cd "$HOME/pr12" || exit
```

Ожидание: `sshd -t` без ошибок, служба ssh активна, есть ключ узла ssh_host_ed25519_key.pub, проверка сумм не выводит строк. Если ключа ed25519 нет, используйте ecdsa — это нужно указать в отчёте. Если `sshd -t` уже сообщает ошибку, исходная конфигурация неисправна: разберите это с преподавателем до начала работы.

### 2.2. Установка недостающих программ

Если openssh-server отсутствует, установите его так же, как в ПР6. Предпочтительно с ISO того же выпуска (`sudo apt-cdrom add`, затем `apt-cache policy openssh-server`, `sudo apt-get -s install openssh-server`, `sudo apt-get install openssh-server`). Другой вариант — временно переключить тот же единственный адаптер на NAT с источником установленного выпуска. Не выполняйте upgrade/dist-upgrade и не отключайте проверку подписей. На Kali nmap установлен в ПР7. После установки верните Internal Network, ручные адреса и проверьте отсутствие default route.

### 2.3. Изоляция, снимок и защита от потери управления

```bash
ip -4 address show
ip -4 route
ip -6 route
```

Ожидание: только учебный сегмент, нет default в обеих таблицах. Штатно выключите обе VM, создайте снимки `pre-lab12-VNN`, убедитесь, что операция завершилась, запустите VM.

**Все изменения SSH выполняются из локальной консоли Astra, не через SSH.** Держите консоль с правами sudo открытой до конца работы. Перезагрузка конфигурации (`reload`) не разрывает существующие сеансы. Но ошибочная конфигурация может не дать открыть новый: локальная консоль и снимок — ваш путь назад. Если после ПР8 действует политика межсетевого экрана, проверьте, что SSH с Kali на Astra разрешён. Не меняйте firewall в этой работе — используйте с преподавателем исходный снимок, где учебная связь разрешена.

<a id="theory"></a>
## 3. Теория: что усиливается и как это проверить

**Три уровня протокола SSH.** Транспортный уровень согласует алгоритмы обмена ключами, шифрования и целостности и подтверждает подлинность сервера его ключом узла. Уровень аутентификации проверяет пользователя: открытым ключом, паролем, keyboard-interactive (через PAM) и другими методами. Уровень соединения открывает каналы: оболочку, команду, пересылку портов, агента, X11. Усиление затрагивает все три уровня.

**Ключ узла и первое подключение.** Клиент запоминает ключ сервера в known_hosts. Первое подключение безопасно, только если отпечаток сверен по независимому каналу. Здесь это вывод `ssh-keygen -lf` на консоли Astra. Принять незнакомый ключ «вслепую» — значит допустить подмену сервера.

**Ключевая аутентификация.** Пара ключей создаётся на клиенте. Открытый ключ кладётся в `~/.ssh/authorized_keys` пользователя на сервере, закрытый никогда не покидает клиент. Парольная фраза шифрует закрытый ключ на диске. ssh-agent хранит расшифрованный ключ в памяти сеанса, чтобы не вводить фразу при каждом подключении. sshd проверяет права: при StrictModes yes он отвергает ключи, если домашний каталог, `.ssh` или authorized_keys доступны на запись другим. В authorized_keys для ключа можно задать ограничения: `from="адрес"`, `command="…"`, `restrict`, `no-port-forwarding`.

**Правило первого значения.** sshd берёт **первое** встреченное значение глобального параметра. Поэтому блок усиления ставится **в начало** файла: строка `X11Forwarding no`, дописанная после штатной `X11Forwarding yes`, не подействует. Блоки Match действуют от строки Match до следующей Match или конца файла и потому ставятся в конец. Фактический результат показывает только `sshd -T` — расширенная проверка, печатающая эффективные значения. С ключом `-C user=…,host=…,addr=…` она учитывает блоки Match для указанного подключения. `sshd -t` проверяет только синтаксис.

Таблица 3 — Параметры усиления и их смысл

| Параметр | Значение | Что закрывает |
|---|---|---|
| PermitRootLogin | no | Прямой вход root; администратор входит своей записью и повышает права через sudo |
| PasswordAuthentication, ChallengeResponseAuthentication | no | Подбор и перехват паролей; keyboard-interactive через PAM тоже отключается |
| PermitEmptyPasswords | no | Вход записей с пустым паролем |
| PubkeyAuthentication, AuthenticationMethods | yes, publickey | Единственный разрешённый способ входа |
| AllowGroups | группа варианта | Круг пользователей; остальные отвергаются даже с правильным ключом |
| MaxAuthTries, LoginGraceTime, MaxStartups | по варианту, 10:30:60 | Число попыток за подключение, время на вход, неаутентифицированные подключения |
| ClientAliveInterval, ClientAliveCountMax | по варианту, 2 | Обрыв «зависших» сеансов |
| X11Forwarding, AllowTcpForwarding, AllowAgentForwarding, PermitTunnel | no | Туннели в обход межсетевого экрана, захват агента и дисплея |
| PermitUserEnvironment | no | Подмена окружения через ~/.ssh/environment |
| LogLevel | VERBOSE | Запись отпечатка ключа при входе |
| KexAlgorithms, Ciphers, MACs | без SHA-1, CBC и umac-64 | Устаревшие алгоритмы транспортного уровня |

**Порядок ограничений пользователей.** sshd проверяет DenyUsers, AllowUsers, DenyGroups, AllowGroups именно в этом порядке. Запрет действует до проверки ключа: пользователь вне AllowGroups отвергается с любым ключом. Root тоже не входит в группу варианта, поэтому его отвергает уже AllowGroups. PermitRootLogin no остаётся вторым, независимым рубежом.

**Ограниченная запись.** Блок `Match User` с ForceCommand заменяет любую запрошенную команду заданной. PermitTTY no запрещает терминал. Так запись получает доступ только к одной функции, например резервному копированию.

**MaxAuthTries и агент.** Каждый предложенный ключ — попытка. Если в агенте много ключей, вход может сорваться раньше, чем дойдёт до нужного. Поэтому клиент проверки использует `IdentitiesOnly=yes` и только учебный ключ.

**Алгоритмы.** Для AEAD-шифров (chacha20-poly1305, aes-gcm) отдельный MAC не согласуется. Поэтому проверка слабого MAC принудительно выбирает aes128-ctr. Новые клиенты OpenSSH могут предупреждать об отсутствии постквантового обмена ключами. Для сервера 7.4 это ожидаемо, на результат проверки не влияет и фиксируется в отчёте.

**Две независимые проверки.** Конфигурация-кандидат проверяется `sshd -T` и скриптом аудита: ожидаемые значения и отсутствие слабых алгоритмов. Поведение проверяется с Kali семью подключениями. Каждое разрешение и каждый отказ подтверждаются строкой журнала: Accepted publickey с отпечатком, not allowed because… с причиной, Invalid user, Unable to negotiate.

<a id="variant"></a>
## 4. Индивидуальное задание

Пользователь A — разрешённый вход по ключу. Пользователь B получает тот же ключ. В нечётных вариантах он **не входит** в группу и должен быть отвергнут. В чётных — входит в группу, но **ограничен** блоком Match: ForceCommand выводит строку `pr12-restricted-vNN` вместо любой команды, терминал запрещён.

Навигация: [1](#v01) · [2](#v02) · [3](#v03) · [4](#v04) · [5](#v05) · [6](#v06) · [7](#v07) · [8](#v08) · [9](#v09) · [10](#v10) · [11](#v11) · [12](#v12) · [13](#v13) · [14](#v14) · [15](#v15) · [16](#v16) · [17](#v17) · [18](#v18) · [19](#v19) · [20](#v20) · [21](#v21) · [22](#v22) · [23](#v23) · [24](#v24) · [25](#v25) · [26](#v26) · [27](#v27).

Таблица 4 — Индивидуальные параметры

| V | Astra / Kali | Группа | Пользователь A | Пользователь B и политика | MaxAuthTries | LoginGraceTime, с | ClientAliveInterval, с |
|---|---|---|---|---|---:|---:|---:|
| <a id="v01"></a>1 | 10.50.1.10 / 10.50.1.20 | sshlab01 | ssha01 | sshb01 — запрещён (нет в группе) | 2 | 20 | 120 |
| <a id="v02"></a>2 | 10.50.2.10 / 10.50.2.20 | sshlab02 | ssha02 | sshb02 — ограничен: ForceCommand | 3 | 30 | 180 |
| <a id="v03"></a>3 | 10.50.3.10 / 10.50.3.20 | sshlab03 | ssha03 | sshb03 — запрещён (нет в группе) | 4 | 45 | 240 |
| <a id="v04"></a>4 | 10.50.4.10 / 10.50.4.20 | sshlab04 | ssha04 | sshb04 — ограничен: ForceCommand | 2 | 60 | 300 |
| <a id="v05"></a>5 | 10.50.5.10 / 10.50.5.20 | sshlab05 | ssha05 | sshb05 — запрещён (нет в группе) | 3 | 20 | 120 |
| <a id="v06"></a>6 | 10.50.6.10 / 10.50.6.20 | sshlab06 | ssha06 | sshb06 — ограничен: ForceCommand | 4 | 30 | 180 |
| <a id="v07"></a>7 | 10.50.7.10 / 10.50.7.20 | sshlab07 | ssha07 | sshb07 — запрещён (нет в группе) | 2 | 45 | 240 |
| <a id="v08"></a>8 | 10.50.8.10 / 10.50.8.20 | sshlab08 | ssha08 | sshb08 — ограничен: ForceCommand | 3 | 60 | 300 |
| <a id="v09"></a>9 | 10.50.9.10 / 10.50.9.20 | sshlab09 | ssha09 | sshb09 — запрещён (нет в группе) | 4 | 20 | 120 |
| <a id="v10"></a>10 | 10.50.10.10 / 10.50.10.20 | sshlab10 | ssha10 | sshb10 — ограничен: ForceCommand | 2 | 30 | 180 |
| <a id="v11"></a>11 | 10.50.11.10 / 10.50.11.20 | sshlab11 | ssha11 | sshb11 — запрещён (нет в группе) | 3 | 45 | 240 |
| <a id="v12"></a>12 | 10.50.12.10 / 10.50.12.20 | sshlab12 | ssha12 | sshb12 — ограничен: ForceCommand | 4 | 60 | 300 |
| <a id="v13"></a>13 | 10.50.13.10 / 10.50.13.20 | sshlab13 | ssha13 | sshb13 — запрещён (нет в группе) | 2 | 20 | 120 |
| <a id="v14"></a>14 | 10.50.14.10 / 10.50.14.20 | sshlab14 | ssha14 | sshb14 — ограничен: ForceCommand | 3 | 30 | 180 |
| <a id="v15"></a>15 | 10.50.15.10 / 10.50.15.20 | sshlab15 | ssha15 | sshb15 — запрещён (нет в группе) | 4 | 45 | 240 |
| <a id="v16"></a>16 | 10.50.16.10 / 10.50.16.20 | sshlab16 | ssha16 | sshb16 — ограничен: ForceCommand | 2 | 60 | 300 |
| <a id="v17"></a>17 | 10.50.17.10 / 10.50.17.20 | sshlab17 | ssha17 | sshb17 — запрещён (нет в группе) | 3 | 20 | 120 |
| <a id="v18"></a>18 | 10.50.18.10 / 10.50.18.20 | sshlab18 | ssha18 | sshb18 — ограничен: ForceCommand | 4 | 30 | 180 |
| <a id="v19"></a>19 | 10.50.19.10 / 10.50.19.20 | sshlab19 | ssha19 | sshb19 — запрещён (нет в группе) | 2 | 45 | 240 |
| <a id="v20"></a>20 | 10.50.20.10 / 10.50.20.20 | sshlab20 | ssha20 | sshb20 — ограничен: ForceCommand | 3 | 60 | 300 |
| <a id="v21"></a>21 | 10.50.21.10 / 10.50.21.20 | sshlab21 | ssha21 | sshb21 — запрещён (нет в группе) | 4 | 20 | 120 |
| <a id="v22"></a>22 | 10.50.22.10 / 10.50.22.20 | sshlab22 | ssha22 | sshb22 — ограничен: ForceCommand | 2 | 30 | 180 |
| <a id="v23"></a>23 | 10.50.23.10 / 10.50.23.20 | sshlab23 | ssha23 | sshb23 — запрещён (нет в группе) | 3 | 45 | 240 |
| <a id="v24"></a>24 | 10.50.24.10 / 10.50.24.20 | sshlab24 | ssha24 | sshb24 — ограничен: ForceCommand | 4 | 60 | 300 |
| <a id="v25"></a>25 | 10.50.25.10 / 10.50.25.20 | sshlab25 | ssha25 | sshb25 — запрещён (нет в группе) | 2 | 20 | 120 |
| <a id="v26"></a>26 | 10.50.26.10 / 10.50.26.20 | sshlab26 | ssha26 | sshb26 — ограничен: ForceCommand | 3 | 30 | 180 |
| <a id="v27"></a>27 | 10.50.27.10 / 10.50.27.20 | sshlab27 | ssha27 | sshb27 — запрещён (нет в группе) | 4 | 45 | 240 |

Таблица 5 — Матрица контрольных подключений и ожидание после усиления

| Тест | Пользователь | Что проверяется | До усиления | После усиления |
|---|---|---|---|---|
| T1 | A | Вход по учебному ключу, команда `id -un` | ALLOW, вывод имени A | ALLOW, вывод имени A |
| T2 | A | Только пароль, без запроса пароля | DENY, сервер предлагает password | DENY, сервер предлагает только publickey |
| T3 | B | Вход по тому же ключу | ALLOW, вывод имени B | нечётные: DENY; чётные: ALLOW, вывод `pr12-restricted-vNN` |
| T4 | root | Вход по учебному ключу | DENY | DENY |
| T5 | nouserNN | Несуществующий пользователь | DENY | DENY |
| T6 | A | Запрос удалённой пересылки порта | ALLOW | FORWARD_REFUSED |
| T7 | A | Только aes128-ctr и hmac-sha1 | ALLOW | NEGOTIATION_FAILED |

Если исходные значения на вашей Astra отличаются от столбца «До усиления», например hmac-sha1 уже отключён, это не ошибка. Зафиксируйте фактическое состояние и объясните его по исходной конфигурации. Скрипт отметит такой тест как FAIL только для этапа before.

<a id="steps"></a>
## 5. Ход выполнения

### Шаг 1. Параметры, версии и резервная копия — 10 минут

Astra, локальная консоль, обычная запись:

```bash
cd "$HOME/pr12" || exit
V=1
python3 kit/tools/pr12.py init --work "$HOME/pr12" --variant "$V" > evidence-init.json
W="$HOME/pr12"; T="$W/kit/tools/pr12.py"
G=$(python3 "$T" info --work "$W" --field group)
A=$(python3 "$T" info --work "$W" --field user_a)
B=$(python3 "$T" info --work "$W" --field user_b)
POL=$(python3 "$T" info --work "$W" --field policy_b)
MARK=$(python3 "$T" info --work "$W" --field marker)
MAT=$(python3 "$T" info --work "$W" --field maxauthtries)
LGT=$(python3 "$T" info --work "$W" --field logingracetime)
ALIVE=$(python3 "$T" info --work "$W" --field alive)
ASTRA_IP=$(python3 "$T" info --work "$W" --field astra)
KALI_IP=$(python3 "$T" info --work "$W" --field kali)
printf 'V=%s group=%s A=%s B=%s policyB=%s MaxAuthTries=%s LoginGraceTime=%s Alive=%s\n' "$V" "$G" "$A" "$B" "$POL" "$MAT" "$LGT" "$ALIVE" | tee evidence/parameters.txt
ip -4 address show | tee evidence/addresses.txt
ip -4 route get "$KALI_IP" | tee evidence/peer-route.txt
dpkg-query -W openssh-server openssh-client | tee evidence/versions.txt
```

Замените 1 своим вариантом; держите терминал открытым, переменные действуют в нём. Резервная копия и хеш исходной конфигурации:

```bash
sudo cp -a /etc/ssh/sshd_config "$W/backup/sshd_config.orig"
sudo sha256sum /etc/ssh/sshd_config | tee evidence/sshd_config.orig.sha256
grep -nEv '^[[:space:]]*(#|$)' /etc/ssh/sshd_config | tee evidence/sshd_config.orig.active.txt
sudo /usr/sbin/sshd -T -C user=root,host=kali,addr="$KALI_IP" > evidence/effective-before.txt
grep -E '^(permitrootlogin|passwordauthentication|challengeresponseauthentication|x11forwarding|allowtcpforwarding|macs|loglevel) ' evidence/effective-before.txt
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | tee evidence/hostkey-fingerprint.txt
```

Ожидание: активных строк немного, усиления нет. Запишите исходные значения PermitRootLogin, PasswordAuthentication, X11Forwarding, AllowTcpForwarding, MACs и LogLevel. Отпечаток ключа узла понадобится на Kali.

### Шаг 2. Учётные записи и ключи — 15 минут

Astra, консоль. Создайте группу и две записи. Пароли задайте временные, уникальные и сложные: они нужны только для доставки ключа.

```bash
sudo groupadd "$G"
sudo useradd -m -s /bin/bash -G "$G" "$A"
sudo useradd -m -s /bin/bash "$B"
if [ "$POL" = restricted ]; then sudo usermod -aG "$G" "$B"; fi
sudo passwd "$A"
sudo passwd "$B"
id "$A" | tee evidence/users.txt
id "$B" | tee -a evidence/users.txt
```

Ожидание: A входит в группу варианта; B входит в неё только в чётных вариантах.

Kali, обычная запись. Ключ ed25519 с парольной фразой (введите её интерактивно), агент, проверка ключа узла:

```bash
cd "$HOME/pr12" || exit
mkdir -p evidence keys && chmod 700 keys
V=1; NN=$(printf %02d "$V")
ASTRA_IP="10.50.$V.10"; A="ssha$NN"; B="sshb$NN"
ssh-keygen -t ed25519 -a 64 -C "pr12-v$NN" -f keys/id_pr12
ssh-keygen -lf keys/id_pr12.pub | tee evidence/client-key-fingerprint.txt
eval "$(ssh-agent -s)"
ssh-add keys/id_pr12
ssh-keyscan -t ed25519 -p 22 "$ASTRA_IP" 2>/dev/null > known_hosts
ssh-keygen -lf known_hosts | tee evidence/hostkey-seen-from-kali.txt
```

Сравните отпечаток в `hostkey-seen-from-kali.txt` с отпечатком, показанным на консоли Astra. **Если они различаются, остановитесь**: не продолжайте и сообщите преподавателю. Доставьте открытый ключ обеим записям, пока вход по паролю ещё разрешён:

```bash
ssh-copy-id -i keys/id_pr12.pub -o UserKnownHostsFile="$HOME/pr12/known_hosts" -o StrictHostKeyChecking=yes "$A@$ASTRA_IP"
ssh-copy-id -i keys/id_pr12.pub -o UserKnownHostsFile="$HOME/pr12/known_hosts" -o StrictHostKeyChecking=yes "$B@$ASTRA_IP"
```

ssh-copy-id запросит пароль записи. Это единственный ввод пароля по сети в работе. Astra, консоль — проверьте права, которых требует StrictModes:

```bash
sudo stat -c '%A %U:%G %n' "/home/$A" "/home/$A/.ssh" "/home/$A/.ssh/authorized_keys" | tee evidence/key-permissions.txt
sudo ssh-keygen -lf "/home/$A/.ssh/authorized_keys" | tee -a evidence/key-permissions.txt
```

Ожидание: `.ssh` — drwx------, authorized_keys — -rw-------, владелец — сам пользователь. Отпечаток совпадает с client-key-fingerprint.txt.

### Шаг 3. Исходная проверка с Kali — 10 минут

На Astra отметьте время начала: `PH_BEFORE=$(date '+%F %T')`. На Kali, в том же терминале, где запущен агент:

```bash
nmap -sT -Pn -n -p 22 --script ssh2-enum-algos,ssh-hostkey -oA evidence/nmap-ssh-before "$ASTRA_IP"
python3 kit/tools/pr12_probe.py --host "$ASTRA_IP" --variant "$V" --phase before \
  --key keys/id_pr12 --known-hosts known_hosts --output evidence/probe-before.jsonl
```

Ожидание: таблица 5, столбец «До усиления». В T2 сервер предлагает password: пароль не запрашивался (BatchMode), но метод доступен. В выводе nmap есть hmac-sha1 и, вероятно, diffie-hellman-group14-sha1 и umac-64. На Astra сохраните журнал этапа:

```bash
sudo journalctl -u ssh --since "$PH_BEFORE" -o short-iso --no-pager > evidence/journal-before.txt
python3 "$T" logs --work "$W" --phase before --file evidence/journal-before.txt
```

При уровне INFO в журнале есть Accepted publickey и Invalid user, но нет отпечатков ключей.

### Шаг 4. Конфигурация-кандидат и аудит — 20 минут

Astra, консоль. Составьте блок усиления. Он встанет в **начало** конфигурации:

```bash
cat > config/hardening.conf <<EOF
# PR12 v$V: усиление; глобальные параметры стоят первыми, потому что действует первое значение
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthenticationMethods publickey
AllowGroups $G
MaxAuthTries $MAT
LoginGraceTime $LGT
MaxStartups 10:30:60
ClientAliveInterval $ALIVE
ClientAliveCountMax 2
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
PermitUserEnvironment no
LogLevel VERBOSE
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
EOF
if [ "$POL" = restricted ]; then
  printf '\n# PR12 v%s: ограниченная запись\nMatch User %s\n    ForceCommand /bin/echo %s\n    PermitTTY no\n' "$V" "$B" "$MARK" > config/match.conf
else
  printf '# PR12 v%s: политика deny, блок Match не нужен\n' "$V" > config/match.conf
fi
{ cat config/hardening.conf; echo; cat /etc/ssh/sshd_config; echo; cat config/match.conf; } > config/sshd_config.candidate
diff -u /etc/ssh/sshd_config config/sshd_config.candidate > evidence/candidate.diff
head -n 30 evidence/candidate.diff
```

Проверьте кандидата **до** применения: синтаксис и эффективные значения для каждого пользователя.

```bash
sudo /usr/sbin/sshd -t -f config/sshd_config.candidate && echo CANDIDATE_SYNTAX_OK
sudo /usr/sbin/sshd -T -f config/sshd_config.candidate -C user="$A",host=kali,addr="$KALI_IP" > evidence/effective-a.txt
sudo /usr/sbin/sshd -T -f config/sshd_config.candidate -C user="$B",host=kali,addr="$KALI_IP" > evidence/effective-b.txt
python3 "$T" audit-config --work "$W" --file evidence/effective-a.txt --role a
python3 "$T" audit-config --work "$W" --file evidence/effective-b.txt --role b
grep -E '^(x11forwarding|passwordauthentication) ' evidence/effective-a.txt
```

Ожидание: CANDIDATE_SYNTAX_OK; аудит показывает все требования OK. Для B в чётных вариантах добавляются forcecommand и permittty no, в нечётных — проверка, что B не в группе. В отчёте объясните, почему `x11forwarding no` победило штатную строку `X11Forwarding yes` ниже по файлу. Если sshd сообщает «Bad configuration option», параметр не поддерживается установленной версией: найдите его в `man sshd_config` своей системы и согласуйте замену с преподавателем. Не применяйте кандидата с ошибкой.

### Шаг 5. Применение и проверка — 15 минут

Astra, консоль. Применение с проверкой и перезагрузкой конфигурации; сеансы не разрываются:

```bash
PH_AFTER=$(date '+%F %T')
sudo install -m 0644 -o root -g root config/sshd_config.candidate /etc/ssh/sshd_config
sudo /usr/sbin/sshd -t && sudo systemctl reload ssh && echo RELOADED
systemctl is-active ssh
```

Если `sshd -t` сообщил ошибку, немедленно верните копию: `sudo install -m 0644 -o root -g root "$W/backup/sshd_config.orig" /etc/ssh/sshd_config` и `sudo systemctl reload ssh`, затем разберите причину.

Kali:

```bash
nmap -sT -Pn -n -p 22 --script ssh2-enum-algos,ssh-hostkey -oA evidence/nmap-ssh-after "$ASTRA_IP"
diff evidence/nmap-ssh-before.nmap evidence/nmap-ssh-after.nmap > evidence/nmap-ssh.diff
python3 kit/tools/pr12_probe.py --host "$ASTRA_IP" --variant "$V" --phase after \
  --key keys/id_pr12 --known-hosts known_hosts --output evidence/probe-after.jsonl
```

Ожидание: 7/7 тестов соответствуют столбцу «После усиления». Из списка алгоритмов исчезли SHA-1, umac-64 и прочие слабые значения. Astra:

```bash
sudo journalctl -u ssh --since "$PH_AFTER" -o short-iso --no-pager > evidence/journal-after.txt
python3 "$T" logs --work "$W" --phase after --file evidence/journal-after.txt
```

Ожидание: Accepted publickey для A с отпечатком ED25519 SHA256:…, совпадающим с client-key-fingerprint.txt. Для root и (в нечётных вариантах) B — not allowed because none of user's groups are listed in AllowGroups. Для nouserNN — Invalid user. Для T7 — Unable to negotiate … no matching MAC found. Отказ пересылки (T6) клиент получает от сервера; в журнале на уровне VERBOSE он может не отражаться — это фиксируется в отчёте.

### Шаг 6. Таблица, восстановление и очистка — 20 минут

Сначала восстановите исходную конфигурацию на Astra:

```bash
sudo install -m 0644 -o root -g root "$W/backup/sshd_config.orig" /etc/ssh/sshd_config
sudo /usr/sbin/sshd -t && sudo systemctl reload ssh && echo RESTORED
sudo sha256sum /etc/ssh/sshd_config | tee evidence/sshd_config.restored.sha256
```

Хеш должен совпасть с sshd_config.orig.sha256. Kali — контрольная проверка восстановления, затем удаление ключа:

```bash
python3 kit/tools/pr12_probe.py --host "$ASTRA_IP" --variant "$V" --phase restored \
  --key keys/id_pr12 --known-hosts known_hosts --output evidence/probe-restored.jsonl
ssh-add -D
eval "$(ssh-agent -k)"
rm -f keys/id_pr12 keys/id_pr12.pub
```

Ожидание: результаты совпадают с этапом before. Перенесите с Kali три файла: probe-before.jsonl, probe-after.jsonl и probe-restored.jsonl. Поместите их на Astra в evidence под именами `kali-before.jsonl`, `kali-after.jsonl`, `kali-restored.jsonl`. Затем на Astra постройте таблицу и удалите учебные записи:

```bash
python3 "$T" table --work "$W"
sudo pkill -u "$A" 2>/dev/null; sudo pkill -u "$B" 2>/dev/null
sudo userdel -r "$A"
sudo userdel -r "$B"
sudo groupdel "$G"
python3 "$T" clean-check --work "$W"
sudo /usr/sbin/sshd -t && systemctl is-active ssh
```

Ожидание: tests.csv — 21 тест, все PASS (или объяснённые отличия этапа before); clean: True — записей, домашних каталогов и группы нет, конфигурация совпадает с исходной по хешу. userdel может сообщить об отсутствии почтового ящика — это не ошибка.

На каждой VM в `$HOME/pr12` сформируйте суммы результатов:

```bash
sha256sum evidence/* > SHA256SUMS.txt
if [ -f session.json ]; then sha256sum session.json >> SHA256SUMS.txt; fi
sha256sum -c SHA256SUMS.txt
```

На Kali дополнительно сохраните известный ключ узла: файл known_hosts содержит открытые данные и может войти в отчёт. Закрытый ключ уже удалён.

<a id="report"></a>
## 6. Результаты и отчёт

Таблица 6 заполняется по tests.csv, отчётам аудита и сводкам журнала; добавьте UTC-время и ссылки на строки файлов.

Таблица 6 — Сопоставление конфигурации, поведения и журнала (пример формулировок, нечётный вариант)

| Требование | Эффективное значение (`sshd -T`) | Контрольное подключение | Запись журнала |
|---|---|---|---|
| Вход только по ключу | passwordauthentication no, authenticationmethods publickey | T1 ALLOW, T2 DENY (publickey) | Accepted publickey … ED25519 SHA256:… |
| Ограничение пользователей | allowgroups sshlab01 | T3 DENY для sshb01 | not allowed because none of user's groups are listed in AllowGroups |
| Запрет root | permitrootlogin no | T4 DENY | not allowed … AllowGroups (первый рубеж) |
| Пересылка отключена | allowtcpforwarding no | T6 FORWARD_REFUSED | — (видно на стороне клиента) |
| Слабые алгоритмы отключены | macs без sha1 и umac-64 | T7 NEGOTIATION_FAILED | Unable to negotiate … no matching MAC found |

Отчёт: титульный лист; название, цель и задачи; номер и условие варианта; схема и паспорт стенда; версии OpenSSH на обеих VM; исходные значения параметров; сверка ключа узла; права authorized_keys; блок усиления и объяснение каждого параметра; diff кандидата; результаты `sshd -t` и аудита для A и B; три матрицы подключений; сравнение списков алгоритмов nmap; таблица 6; восстановление и очистка; выводы; ответы на вопросы.

Обязательные доказательства: режим внутренней сети и завершённый снимок; sshd_config.orig.sha256 и sshd_config.restored.sha256 с одинаковым хешем; hostkey-fingerprint.txt и hostkey-seen-from-kali.txt; client-key-fingerprint.txt; key-permissions.txt; effective-before.txt, effective-a.txt, effective-b.txt; audit-config-a.json и audit-config-b.json; candidate.diff; три файла kali-*.jsonl; nmap-ssh-before/after и nmap-ssh.diff; journal-before/after и их сводки; tests.csv; clean-check.json; суммы обеих VM. Пароли, парольная фраза и закрытый ключ в отчёт не входят.

<a id="assessment"></a>
## 7. Контрольные вопросы и оценивание

1. Какие задачи решают транспортный уровень, уровень аутентификации и уровень соединения SSH?
2. Зачем сверять отпечаток ключа узла при первом подключении и чем опасно принять его «вслепую»?
3. Почему блок усиления ставится в начало sshd_config, а блоки Match — в конец?
4. Чем `sshd -t` отличается от `sshd -T` и зачем ключ `-C`?
5. Почему ChallengeResponseAuthentication нужно отключать вместе с PasswordAuthentication?
6. В каком порядке sshd проверяет DenyUsers, AllowUsers, DenyGroups, AllowGroups, и почему root в этой работе отвергает уже AllowGroups?
7. Что делают ForceCommand и PermitTTY в блоке Match и где такая запись полезна?
8. Как MaxAuthTries взаимодействует с ключами в ssh-agent и зачем IdentitiesOnly?
9. Почему проверка слабого MAC принудительно выбирает шифр aes128-ctr?
10. Чем опасны AllowTcpForwarding и AllowAgentForwarding для сервера во внутренней сети?
11. Какие права на `~/.ssh` и authorized_keys требует StrictModes и почему?
12. Почему запрет подтверждается подключением и журналом, а не только текстом конфигурации?

Таблица 7 — Оценивание

| Оценка | Критерии |
|---|---|
| 5 | Ключ узла сверен; ключ с парольной фразой доставлен; кандидат проверен `sshd -t`, `sshd -T` и аудитом для A и B; конфигурация применена без потери управления; 7/7 тестов после усиления, каждый подтверждён журналом или объяснён; алгоритмы сравнены; восстановление подтверждено хешем и повторной матрицей; очистка доказана; ответы полны |
| 4 | Основной сценарий выполнен и подтверждён; небольшие пробелы в объяснениях не меняют выводов |
| 3 | Усиление применено и проверено подключениями; часть доказательств (журнал, алгоритмы или аудит B) неполна; недочёты исправляются с преподавателем |
| 2 | Конфигурация применена без проверки кандидата; нет контрольных подключений или восстановления; потеряно управление без восстановления; результаты не подтверждены |

Критические нарушения: подбор паролей или использование Hydra/sshpass; NSE-скрипты категорий brute/intrusive; подключения к чужим адресам; принятие ключа узла без сверки при несовпадении отпечатка; изменение конфигурации SSH через SSH без открытой консоли; публикация паролей, парольной фразы или закрытого ключа; вымышленные результаты.

<a id="sources"></a>
## 8. Диагностика и источники

Таблица 8 — Типовые затруднения

| Симптом | Проверить и сделать |
|---|---|
| Bad configuration option: … | Параметр не поддерживается версией sshd; `man sshd_config` своей системы; не применять кандидата |
| Отпечаток ключа узла не совпадает | Остановиться; адрес, паспорт, другой узел в сети; сообщить преподавателю |
| ssh-copy-id: Permission denied | Пароль записи; PasswordAuthentication в исходной конфигурации; запись создана |
| T1 DENY после усиления | Группа A (`id`), права `.ssh` и authorized_keys, отпечаток ключа, журнал Authentication refused: bad ownership or modes |
| Too many authentication failures | Агент предлагает лишние ключи; IdentitiesOnly и `-i`; MaxAuthTries варианта |
| T2 показывает password после усиления | Порядок строк: блок не в начале; `sshd -T`; reload выполнен |
| T3 ALLOW в нечётном варианте | B ошибочно в группе (`id "$B"`); AllowGroups в effective-b.txt |
| T3 выводит имя B в чётном варианте | Блок Match отсутствует или не в конце; `sshd -T -C user=$B…` |
| T6 ALLOW после усиления | allowtcpforwarding в effective-a.txt; reload |
| T7 ALLOW после усиления | Порядок строк MACs; клиент выбрал AEAD-шифр (проверьте опции теста) |
| WARNING: connection is not using a post-quantum key exchange | Предупреждение нового клиента для сервера 7.4; на результат не влияет |
| NETWORK_ERROR | Служба ssh, адрес, маршрут, политика ПР8 |
| Журнал journal-*.txt пуст | Имя службы (`systemctl status ssh`); выборка по идентификатору: `sudo journalctl -t sshd --since …` |
| HOSTKEY_ERROR | Используется не тот known_hosts или ключ узла изменился; не удалять проверку |
| После reload нет нового входа ни у кого | Консоль: вернуть резервную копию, reload, разобрать `sshd -t` и журнал |
| clean: False | Какой пункт ложен: userdel, groupdel, хеш конфигурации |
| refusing to overwrite | Повторный запуск этапа: сохранить прежний файл, начать новую сессию; не смешивать серии |

- РПД «Операционные системы», 10.05.01, 2024, раздел 4.2, практическая тема 12.
- [ПР1: изолированный стенд](reference/Lab1.md); ПР6: установка openssh-server с ISO «Орла».
- [OpenSSH 7.4 release notes](https://www.openssh.com/txt/release-7.4) — состав версии, используемой на «Орле».
- [sshd_config(5), OpenBSD](https://man.openbsd.org/sshd_config) и [sshd(8)](https://man.openbsd.org/sshd) — параметры, правило первого значения, Match, `-t`, `-T`, `-C`; для своей системы сверяйте с `man sshd_config`.
- [ssh-keygen(1)](https://man.openbsd.org/ssh-keygen), [ssh-agent(1)](https://man.openbsd.org/ssh-agent), [ssh(1)](https://man.openbsd.org/ssh) — ключи, агент, BatchMode, IdentitiesOnly.
- [RFC 4251: SSH Protocol Architecture](https://www.rfc-editor.org/rfc/rfc4251), [RFC 4252: Authentication Protocol](https://www.rfc-editor.org/rfc/rfc4252).
- [NIST IR 7966: Security of Interactive and Automated Access Management Using SSH](https://csrc.nist.gov/pubs/ir/7966/final).
- [Nmap NSE: ssh2-enum-algos](https://nmap.org/nsedoc/scripts/ssh2-enum-algos.html), [ssh-hostkey](https://nmap.org/nsedoc/scripts/ssh-hostkey.html).
- Локальные справки: `man sshd_config`, `man sshd`, `man ssh`, `man ssh-keygen`, `man ssh-copy-id`, `man authorized_keys` (раздел AUTHORIZED_KEYS в `man sshd`), `man journalctl`.

Дата подготовки: 8 ноября 2026 года.
