#!/usr/bin/env bash
# =============================================================================
#  harden.sh — первичная настройка безопасности сервера Debian / Ubuntu
#  Идея взята из security-itf.sh (IT Freedom Project), логика переписана.
#
#  Использование (на сервере, от root или через sudo):
#    bash harden.sh                       интерактивно
#    bash harden.sh -c harden.conf -y     по конфигу, без вопросов
#    bash harden.sh --confirm             подтвердить, что новый вход работает
#    bash harden.sh --rollback            вручную откатить SSH и firewall
#
#  Поддержка: Debian 11–13, Ubuntu 20.04+; Proxmox VE и LXC — с поправками.
# =============================================================================
set -Eeuo pipefail
umask 022

readonly SCRIPT_VERSION="2.0"
readonly STATE_DIR=/root/.harden
readonly SSHD_DROPIN=/etc/ssh/sshd_config.d/00-harden.conf
readonly SSHD_TRANSITION=/etc/ssh/sshd_config.d/01-harden-transition.conf
readonly SSH_GROUP=sshusers
readonly RB_UNIT=harden-rollback
TS=$(date +%Y%m%d-%H%M%S); readonly TS
readonly BACKUP_DIR="$STATE_DIR/backup-$TS"
readonly LOG="$STATE_DIR/harden-$TS.log"

# ------------------------------------------------------------------ вывод ----
if [[ -t 1 ]]; then CR=$'\e[31m'; CG=$'\e[32m'; CY=$'\e[33m'; CB=$'\e[36m'; CN=$'\e[0m'
else CR=''; CG=''; CY=''; CB=''; CN=''; fi
info() { printf '%s[*]%s %s\n' "$CB" "$CN" "$*"; }
ok()   { printf '%s[✓]%s %s\n' "$CG" "$CN" "$*"; }
warn() { printf '%s[!]%s %s\n' "$CY" "$CN" "$*" >&2; }
die()  { printf '%s[✗]%s %s\n' "$CR" "$CN" "$*" >&2; exit 1; }
step() { printf '\n%s━━━ %s%s\n' "$CB" "$*" "$CN"; }
trap 'warn "Ошибка в строке $LINENO: $BASH_COMMAND"' ERR

usage() {
  cat <<'EOF'
harden.sh — первичная настройка безопасности Debian/Ubuntu
  -c, --config FILE   конфиг (по умолчанию harden.conf рядом со скриптом)
  -y, --yes           без вопросов (значения из конфига / по умолчанию)
      --confirm       подтвердить, что вход по ключу работает (отменяет автооткат)
      --rollback      откатить SSH и firewall из последнего бэкапа
  -h, --help          эта справка
EOF
}

# --------------------------------------------------------------- аргументы ---
ASSUME_YES=${ASSUME_YES:-no}; MODE=apply; CONFIG=""
while [[ $# -gt 0 ]]; do
  case $1 in
    -c|--config) CONFIG=${2:?нужен путь к конфигу}; shift 2 ;;
    -y|--yes)    ASSUME_YES=yes; shift ;;
    --confirm)   MODE=confirm; shift ;;
    --rollback)  MODE=rollback; shift ;;
    -h|--help)   usage; exit 0 ;;
    *) die "Неизвестный аргумент: $1 (см. --help)" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "Запусти от root: sudo bash $0"
install -d -m 700 "$STATE_DIR"

case $MODE in
  confirm)
    [[ -f $STATE_DIR/confirm.sh ]] || die "Нечего подтверждать ($STATE_DIR/confirm.sh нет)"
    exec bash "$STATE_DIR/confirm.sh" ;;
  rollback)
    [[ -f $STATE_DIR/rollback.sh ]] || die "Нет $STATE_DIR/rollback.sh"
    bash "$STATE_DIR/rollback.sh"; tail -n 15 "$STATE_DIR/rollback.log"; exit 0 ;;
esac

: > "$LOG"; chmod 600 "$LOG"
exec > >(tee -a "$LOG") 2>&1

# ------------------------------------------------------------------ конфиг ---
if [[ -z $CONFIG ]]; then
  _src=${BASH_SOURCE[0]:-}
  if [[ -n $_src && -f $_src && -f "$(dirname "$(readlink -f "$_src")")/harden.conf" ]]; then
    CONFIG="$(dirname "$(readlink -f "$_src")")/harden.conf"
  fi
fi
if [[ -n $CONFIG ]]; then
  [[ -f $CONFIG ]] || die "Конфиг не найден: $CONFIG"
  # shellcheck disable=SC1090
  source "$CONFIG"; info "Конфиг: $CONFIG"
fi

ASK_PORT=yes;  if [[ -n ${SSH_PORT+x} ]];   then ASK_PORT=no;  fi
ASK_OPEN=yes;  if [[ -n ${OPEN_PORTS+x} ]]; then ASK_OPEN=no;  fi

: "${ADMIN_USER:=}"              # имя админа (sudo + SSH)
: "${ADMIN_SSH_KEYS:=}"          # публичные ключи, по одному в строке
: "${ADMIN_KEYS_URL:=}"          # напр. https://github.com/<user>.keys
: "${ADMIN_PASSWORD:=}"          # пусто = сгенерировать, если пароля нет
: "${SUDO_NOPASSWD:=no}"
: "${SSH_PORT:=22}"
: "${SSH_ROOT_LOGIN:=no}"        # no | prohibit-password
: "${SSH_TCP_FORWARDING:=no}"    # no | local | remote | yes
: "${SSH_AGENT_FORWARDING:=no}"
: "${SSH_ALLOW_FROM:=}"          # CIDR через пробел; пусто = откуда угодно
: "${SSH_EXTRA_USERS:=}"         # другие пользователи с доступом по SSH
: "${FIREWALL:=yes}"
: "${OPEN_PORTS:=}"              # "80/tcp 443/tcp 51820/udp"
: "${FAIL2BAN:=yes}"
: "${TRUSTED_IPS:=}"             # никогда не банить
: "${UPGRADE:=yes}"
: "${AUTO_UPDATES:=yes}"
: "${AUTO_REBOOT:=no}"
: "${AUTO_REBOOT_TIME:=04:30}"
: "${SYSCTL_HARDEN:=yes}"
: "${NET_TUNING:=no}"            # BBR + fq
: "${TIMEZONE:=}"
: "${NEW_HOSTNAME:=}"
: "${LOCK_ROOT_PASSWORD:=no}"
: "${GUEST_AGENT:=keep}"         # keep | disable
: "${EXTRA_PACKAGES:=htop}"
: "${ROLLBACK_MINUTES:=10}"

TTY_OK=no; if { : </dev/tty; } 2>/dev/null; then TTY_OK=yes; fi
HAS_TTY=$TTY_OK; if [[ $ASSUME_YES == yes ]]; then HAS_TTY=no; fi

OLD_PORTS=(); CURRENT_PORTS=(); VALID_KEYS=""; KEY_FALLBACK=no; GENERATED_PW=""
IS_CT=no; IS_PVE=no; VIRT=none; UFW_WAS_ACTIVE=no; HAS_DOCKER=no; EXISTING_KEYFILES=()

SYSCTL_SETTINGS=(
  net.ipv4.conf.all.rp_filter=2            # loose: не ломает асимметричную маршрутизацию/VPN
  net.ipv4.conf.default.rp_filter=2
  net.ipv4.conf.all.accept_redirects=0
  net.ipv4.conf.default.accept_redirects=0
  net.ipv4.conf.all.secure_redirects=0
  net.ipv4.conf.default.secure_redirects=0
  net.ipv6.conf.all.accept_redirects=0
  net.ipv6.conf.default.accept_redirects=0
  net.ipv4.conf.all.send_redirects=0
  net.ipv4.conf.default.send_redirects=0
  net.ipv4.conf.all.accept_source_route=0
  net.ipv4.conf.default.accept_source_route=0
  net.ipv6.conf.all.accept_source_route=0
  net.ipv6.conf.default.accept_source_route=0
  net.ipv4.icmp_echo_ignore_broadcasts=1
  net.ipv4.icmp_ignore_bogus_error_responses=1
  net.ipv4.tcp_syncookies=1
  net.ipv4.tcp_rfc1337=1
  kernel.kptr_restrict=2
  kernel.dmesg_restrict=1
  kernel.yama.ptrace_scope=1
  kernel.randomize_va_space=2
  net.core.bpf_jit_harden=2
  fs.protected_hardlinks=1
  fs.protected_symlinks=1
  fs.protected_fifos=2
  fs.protected_regular=2
  fs.suid_dumpable=0
  dev.tty.ldisc_autoload=0
)

# ---------------------------------------------------------------- хелперы ----
ask() {   # ask "вопрос" "по умолчанию" -> stdout
  local q=$1 def=${2:-} a=""
  if [[ $HAS_TTY != yes ]]; then printf '%s' "$def"; return 0; fi
  read -r -p "$q${def:+ [$def]}: " a </dev/tty || true
  printf '%s' "${a:-$def}"
}
confirm() { local a; a=$(ask "$1 (y/n)" "${2:-y}"); [[ ${a,,} =~ ^(y|yes|д|да)$ ]]; }

apt_get() {
  DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
  apt-get -yq -o DPkg::Lock::Timeout=600 \
    -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@"
}

valid_username() {
  [[ $1 =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || { warn "Имя: a-z, 0-9, _ -, до 32 символов"; return 1; }
  [[ $1 != root ]] || { warn "root нельзя"; return 1; }
  if id "$1" &>/dev/null && [[ $(id -u "$1") -lt 1000 ]]; then warn "$1 — системный пользователь"; return 1; fi
}
valid_port() { [[ $1 =~ ^[0-9]+$ ]] && [[ $1 -ge 1 && $1 -le 65535 ]]; }

gen_password() { head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-24; }

server_ip() {
  local ip=""
  if [[ -n ${SSH_CONNECTION:-} ]]; then ip=$(awk '{print $3}' <<<"$SSH_CONNECTION"); fi
  if [[ -z $ip ]]; then
    ip=$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}') || true
  fi
  printf '%s' "${ip:-<IP-сервера>}"
}
client_ip() {
  local c=""
  if [[ -n ${SSH_CLIENT:-} ]]; then c=${SSH_CLIENT%% *}; fi
  if [[ -z $c ]]; then c=$(who -m 2>/dev/null | sed -n 's/.*(\(.*\)).*/\1/p') || true; fi
  printf '%s' "${c:-неизвестен}"
}

# Оставляет из списка только то, что поддерживает установленный OpenSSH
filter_supported() {
  local q=$1 a avail; local -a out=(); shift
  avail=$(ssh -Q "$q" 2>/dev/null) || return 0
  for a in "$@"; do if grep -qxF -- "$a" <<<"$avail"; then out+=("$a"); fi; done
  local IFS=,; printf '%s' "${out[*]}"
}

# stdin: строки с ключами (можно с опциями authorized_keys) -> stdout: чистые валидные ключи
validate_keys() {
  local line key fp bits
  local re='((sk-)?(ssh|ecdsa)-[A-Za-z0-9@.-]+[[:space:]]+[A-Za-z0-9+/=]+([[:space:]].*)?)$'
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    if [[ -z ${line//[[:space:]]/} || $line == \#* ]]; then continue; fi
    if [[ $line =~ $re ]]; then key=${BASH_REMATCH[1]}
    else warn "Пропущено (не ключ): ${line:0:50}"; continue; fi
    if ! fp=$(ssh-keygen -lf /dev/stdin <<<"$key" 2>/dev/null); then
      warn "Невалидный ключ: ${key:0:50}…"; continue
    fi
    case $fp in *'(DSA)') warn "DSA-ключ отклонён"; continue ;; esac
    bits=${fp%% *}
    if [[ $fp == *'(RSA)' && $bits -lt 3072 ]]; then warn "RSA-$bits: лучше перейти на ed25519"; fi
    info "Ключ принят: $fp" >&2
    printf '%s\n' "$key"
  done
}

ssh_rule_specs() {   # $1 = порт -> правила ufw для SSH
  local c
  if [[ -z $SSH_ALLOW_FROM ]]; then echo "limit $1/tcp"
  else for c in $SSH_ALLOW_FROM; do echo "allow from $c to any port $1 proto tcp"; done; fi
}

restore_ssh() {
  if [[ -d $BACKUP_DIR/ssh ]]; then
    rm -rf /etc/ssh.harden-rb && cp -a "$BACKUP_DIR/ssh" /etc/ssh.harden-rb \
      && rm -rf /etc/ssh && mv /etc/ssh.harden-rb /etc/ssh
  fi
}

# ----------------------------------------------------------------- шаги ------
preflight() {
  step "Проверки"
  if [[ -f $STATE_DIR/state ]]; then
    die "Предыдущий запуск не подтверждён. Сначала: bash harden.sh --confirm  или  --rollback"
  fi
  [[ -r /etc/os-release ]] || die "Нет /etc/os-release"
  # shellcheck disable=SC1091
  . /etc/os-release
  case " ${ID:-} ${ID_LIKE:-} " in
    *" debian "*|*" ubuntu "*) ok "ОС: ${PRETTY_NAME:-$ID}" ;;
    *) die "Поддерживаются только Debian/Ubuntu (найдено: ${PRETTY_NAME:-?})" ;;
  esac
  [[ -d /run/systemd/system ]] || die "Нужен systemd"

  VIRT=$(systemd-detect-virt -c 2>/dev/null || true); VIRT=${VIRT:-none}
  if [[ $VIRT != none ]]; then IS_CT=yes; fi
  if [[ -d /etc/pve ]] || command -v pveversion >/dev/null 2>&1; then IS_PVE=yes; fi
  if command -v docker >/dev/null 2>&1; then HAS_DOCKER=yes; fi

  if [[ $IS_PVE == yes ]]; then
    warn "Proxmox VE: порт SSH остаётся 22, root — только по ключу (нужно кластеру/миграциям), UFW не ставлю (используй PVE Firewall)."
    SSH_PORT=22; ASK_PORT=no; SSH_ROOT_LOGIN=prohibit-password; FIREWALL=no
  fi
  if [[ $IS_CT == yes ]]; then
    warn "Контейнер ($VIRT): firewall, fail2ban, sysctl и hostname — на стороне хоста, пропускаю."
    FIREWALL=no; FAIL2BAN=no; SYSCTL_HARDEN=no; NET_TUNING=no; NEW_HOSTNAME=""
  fi
  if [[ $HAS_DOCKER == yes && $FIREWALL == yes ]]; then
    warn "Docker: опубликованные порты (-p) ОБХОДЯТ UFW. Публикуй на 127.0.0.1 или используй DOCKER-USER."
  fi
  case $SSH_ROOT_LOGIN in no|prohibit-password) ;; *) die "SSH_ROOT_LOGIN: no | prohibit-password";; esac
  case $SSH_TCP_FORWARDING in no|local|remote|yes) ;; *) die "SSH_TCP_FORWARDING: no|local|remote|yes";; esac
  [[ $ROLLBACK_MINUTES =~ ^[0-9]+$ && $ROLLBACK_MINUTES -ge 3 ]] || die "ROLLBACK_MINUTES >= 3"
}

gather_input() {
  step "Параметры"
  local def=""
  if [[ -n ${SUDO_USER:-} && ${SUDO_USER:-} != root ]]; then def=$SUDO_USER; fi
  if [[ -z $ADMIN_USER ]]; then
    [[ $HAS_TTY == yes ]] || die "ADMIN_USER не задан (конфиг или переменная окружения)"
    while :; do ADMIN_USER=$(ask "Имя админ-пользователя" "$def"); if valid_username "$ADMIN_USER"; then break; fi; done
  else
    valid_username "$ADMIN_USER" || die "Некорректный ADMIN_USER"
  fi

  if [[ $ASK_PORT == yes && $HAS_TTY == yes ]]; then
    while :; do SSH_PORT=$(ask "Порт SSH" "$SSH_PORT"); if valid_port "$SSH_PORT"; then break; fi; warn "1–65535"; done
  fi
  valid_port "$SSH_PORT" || die "Некорректный SSH_PORT"

  if [[ $ASK_OPEN == yes && $HAS_TTY == yes && $FIREWALL == yes ]]; then
    OPEN_PORTS=$(ask "Какие порты открыть кроме SSH (напр. '80/tcp 443/tcp'), пусто = никаких" "")
  fi

  if [[ -z ${ADMIN_SSH_KEYS//[[:space:]]/} && -z $ADMIN_KEYS_URL ]]; then
    local home f
    home=$(getent passwd "$ADMIN_USER" | cut -d: -f6) || true
    for f in ${home:+"$home/.ssh/authorized_keys"} \
             ${SUDO_USER:+"$(getent passwd "$SUDO_USER" | cut -d: -f6)/.ssh/authorized_keys"} \
             /root/.ssh/authorized_keys; do
      if [[ -s $f ]]; then EXISTING_KEYFILES+=("$f"); fi
    done
    if [[ ${#EXISTING_KEYFILES[@]} -gt 0 ]] && confirm "Взять ключи из ${EXISTING_KEYFILES[*]}?" y; then
      KEY_FALLBACK=yes
    else
      [[ $HAS_TTY == yes ]] || die "Не задан ни один SSH-ключ (ADMIN_SSH_KEYS или ADMIN_KEYS_URL)"
      info "Вставь публичный ключ(и) по одному в строке (или gh:<github-логин>). Пустая строка — конец:"
      local line
      while IFS= read -r line </dev/tty; do
        [[ -n $line ]] || break
        if [[ $line =~ ^gh:([A-Za-z0-9-]+)$ ]]; then ADMIN_KEYS_URL="https://github.com/${BASH_REMATCH[1]}.keys"
        else ADMIN_SSH_KEYS+="$line"$'\n'; fi
      done
    fi
  fi
}

install_base() {
  step "Базовые пакеты"
  if command -v cloud-init >/dev/null 2>&1; then
    info "Жду завершения cloud-init…"; timeout 600 cloud-init status --wait >/dev/null 2>&1 || true
  fi
  apt_get update
  apt_get install openssh-server openssh-client sudo curl ca-certificates iproute2
}

detect_ssh() {
  install -d -m 755 /run/sshd
  mapfile -t CURRENT_PORTS < <(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -un)
  if [[ ${#CURRENT_PORTS[@]} -eq 0 ]]; then CURRENT_PORTS=(22); fi
  local p is_new=yes
  for p in "${CURRENT_PORTS[@]}"; do
    if [[ $p == "$SSH_PORT" ]]; then is_new=no; else OLD_PORTS+=("$p"); fi
  done
  if [[ $is_new == yes ]] && ss -Hltn "sport = :$SSH_PORT" 2>/dev/null | grep -q .; then
    die "Порт $SSH_PORT уже занят: $(ss -Hltnp "sport = :$SSH_PORT" | head -1)"
  fi
}

resolve_keys() {
  step "SSH-ключи"
  local raw=$ADMIN_SSH_KEYS f
  if [[ -n $ADMIN_KEYS_URL ]]; then
    info "Загружаю ключи: $ADMIN_KEYS_URL"
    raw+=$'\n'"$(curl -fsSL --max-time 20 "$ADMIN_KEYS_URL")" || die "Не удалось скачать $ADMIN_KEYS_URL"
  fi
  if [[ $KEY_FALLBACK == yes ]]; then
    for f in "${EXISTING_KEYFILES[@]}"; do raw+=$'\n'"$(<"$f")"; done
  fi
  VALID_KEYS=$(printf '%s\n' "$raw" | validate_keys | awk '!seen[$1" "$2]++')
  [[ -n $VALID_KEYS ]] || die "Нет ни одного валидного ключа — вход только по ключу включать нельзя."
}

show_plan() {
  step "План"
  local nkeys old=""; nkeys=$(grep -c . <<<"$VALID_KEYS")
  if [[ ${#OLD_PORTS[@]} -gt 0 ]]; then old=" (старый ${OLD_PORTS[*]} открыт до подтверждения)"; fi
  printf '  %-15s %s\n' \
    "Пользователь:" "$ADMIN_USER — sudo$( [[ $SUDO_NOPASSWD == yes ]] && echo ' без пароля' ), ключей: $nkeys" \
    "SSH:" "порт $SSH_PORT$old; только ключи; root: $SSH_ROOT_LOGIN" \
    "SSH доступ с:" "${SSH_ALLOW_FROM:-любых адресов}" \
    "Firewall:" "$( [[ $FIREWALL == yes ]] && echo "UFW, входящие закрыты; открыть: ${OPEN_PORTS:-только SSH}" || echo нет )" \
    "fail2ban:" "$FAIL2BAN" \
    "Обновления:" "upgrade=$UPGRADE, авто-security=$AUTO_UPDATES, авто-reboot=$AUTO_REBOOT" \
    "sysctl:" "$SYSCTL_HARDEN (BBR: $NET_TUNING)" \
    "Автооткат:" "через $ROLLBACK_MINUTES мин без подтверждения (SSH + firewall)"
  if [[ -n $SSH_ALLOW_FROM ]]; then warn "Твой текущий адрес: $(client_ip) — убедись, что он входит в SSH_ALLOW_FROM"; fi
  if [[ $HAS_TTY == yes ]]; then confirm "Применить?" y || die "Отменено"; fi
}

backup_configs() {
  step "Бэкап → $BACKUP_DIR"
  install -d -m 700 "$BACKUP_DIR"
  local d
  for d in /etc/ssh /etc/ufw /etc/fail2ban /etc/sudoers.d /etc/sysctl.d; do
    if [[ -e $d ]]; then cp -a "$d" "$BACKUP_DIR/"; fi
  done
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then UFW_WAS_ACTIVE=yes; fi
  ok "Готово"
}

system_upgrade() {
  [[ $UPGRADE == yes ]] || return 0
  step "Обновление системы"
  apt_get full-upgrade
  apt_get autoremove --purge
  ok "Система обновлена"
}

install_packages() {
  step "Пакеты"
  local -a pkgs=() extra=()
  if [[ $FIREWALL == yes ]];     then pkgs+=(ufw); fi
  if [[ $FAIL2BAN == yes ]];     then pkgs+=(fail2ban python3-systemd nftables); fi
  if [[ $AUTO_UPDATES == yes ]]; then pkgs+=(unattended-upgrades); fi
  read -ra extra <<<"$EXTRA_PACKAGES"; pkgs+=("${extra[@]}")
  if [[ ${#pkgs[@]} -gt 0 ]]; then apt_get install --no-install-recommends "${pkgs[@]}"; fi
  ok "Установлено: ${pkgs[*]:-ничего}"
}

setup_system() {
  step "Система"
  if [[ -n $TIMEZONE ]]; then
    if timedatectl set-timezone "$TIMEZONE"; then ok "Часовой пояс: $TIMEZONE"; else warn "Не удалось задать $TIMEZONE"; fi
  fi
  timedatectl set-ntp true >/dev/null 2>&1 || true
  if [[ -n $NEW_HOSTNAME ]]; then
    hostnamectl set-hostname "$NEW_HOSTNAME"
    if grep -q '^127\.0\.1\.1' /etc/hosts; then sed -i "s/^127\.0\.1\.1.*/127.0.1.1\t$NEW_HOSTNAME/" /etc/hosts
    else printf '127.0.1.1\t%s\n' "$NEW_HOSTNAME" >> /etc/hosts; fi
    ok "Hostname: $NEW_HOSTNAME"
  fi
  if [[ $GUEST_AGENT == disable ]] && systemctl cat qemu-guest-agent.service >/dev/null 2>&1; then
    systemctl disable --now qemu-guest-agent >/dev/null 2>&1 || true
    systemctl mask qemu-guest-agent >/dev/null 2>&1 || true
    ok "qemu-guest-agent отключён"
  fi
}

setup_admin() {
  step "Пользователь $ADMIN_USER"
  getent group "$SSH_GROUP" >/dev/null || groupadd --system "$SSH_GROUP"
  if id "$ADMIN_USER" &>/dev/null; then info "Уже существует — обновляю группы и ключи"
  else useradd -m -s /bin/bash "$ADMIN_USER"; ok "Создан"; fi
  usermod -aG "sudo,$SSH_GROUP" "$ADMIN_USER"

  local u
  for u in $SSH_EXTRA_USERS; do
    if id "$u" &>/dev/null; then usermod -aG "$SSH_GROUP" "$u"; ok "SSH-доступ: $u"
    else warn "Пользователь $u не найден"; fi
  done
  if [[ $SSH_ROOT_LOGIN != no ]]; then usermod -aG "$SSH_GROUP" root
  else gpasswd -d root "$SSH_GROUP" >/dev/null 2>&1 || true; fi

  # Пароль нужен для sudo и для входа через VNC/консоль провайдера (по SSH он не работает)
  local st; st=$(passwd -S "$ADMIN_USER" | awk '{print $2}')
  if [[ -n $ADMIN_PASSWORD ]]; then
    printf '%s:%s\n' "$ADMIN_USER" "$ADMIN_PASSWORD" | chpasswd; ok "Пароль задан из конфига"
  elif [[ $st != P ]]; then
    GENERATED_PW=$(gen_password)
    printf '%s:%s\n' "$ADMIN_USER" "$GENERATED_PW" | chpasswd; ok "Пароль сгенерирован (покажу в конце)"
  fi

  local home ak key added=0
  home=$(getent passwd "$ADMIN_USER" | cut -d: -f6)
  install -d -m 700 "$home/.ssh"; chown "$ADMIN_USER:" "$home/.ssh"
  ak="$home/.ssh/authorized_keys"; touch "$ak"
  while IFS= read -r key; do
    [[ -n $key ]] || continue
    if ! grep -qF -- "$(awk '{print $2}' <<<"$key")" "$ak"; then printf '%s\n' "$key" >> "$ak"; added=$((added+1)); fi
  done <<<"$VALID_KEYS"
  chmod 600 "$ak"; chown "$ADMIN_USER:" "$ak"
  ssh-keygen -lf "$ak" >/dev/null 2>&1 || die "В $ak нет валидных ключей"
  ok "authorized_keys: добавлено $added"

  local sf="/etc/sudoers.d/90-harden-$ADMIN_USER" tmp="$STATE_DIR/sudoers.tmp"
  if [[ $SUDO_NOPASSWD == yes ]]; then
    echo "$ADMIN_USER ALL=(ALL:ALL) NOPASSWD: ALL" > "$tmp"
    visudo -cqf "$tmp" && install -m 440 "$tmp" "$sf"; rm -f "$tmp"
    ok "sudo без пароля"
  else rm -f "$sf"; fi
}

setup_sudo() {
  local tmp="$STATE_DIR/sudoers.tmp"
  cat > "$tmp" <<'EOF'
# harden.sh
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults passwd_tries=3
Defaults timestamp_timeout=15
EOF
  if visudo -cqf "$tmp"; then install -m 440 "$tmp" /etc/sudoers.d/00-harden; ok "sudo: лог в /var/log/sudo.log, use_pty"; fi
  rm -f "$tmp"
}

setup_sysctl() {
  [[ $SYSCTL_HARDEN == yes ]] || return 0
  step "sysctl"
  local kv k conf=/etc/sysctl.d/90-harden.conf
  {
    echo "# harden.sh — ip_forward не трогаем (Docker/VPN)"
    for kv in "${SYSCTL_SETTINGS[@]}"; do
      k=${kv%%=*}
      if [[ -e /proc/sys/${k//.//} ]]; then echo "$k = ${kv#*=}"; fi
    done
  } > "$conf"
  sysctl -q -p "$conf" || warn "Часть параметров sysctl не применилась"
  ok "Применено: $conf"
  if [[ $NET_TUNING == yes ]]; then
    modprobe tcp_bbr 2>/dev/null || true
    if grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
      echo tcp_bbr > /etc/modules-load.d/harden-bbr.conf
      printf 'net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n' > /etc/sysctl.d/91-harden-bbr.conf
      sysctl -q -p /etc/sysctl.d/91-harden-bbr.conf; ok "BBR + fq"
    else warn "BBR недоступен в этом ядре"; fi
  fi
}

setup_logging() {
  step "Логи и core dumps"
  install -d /etc/systemd/journald.conf.d /etc/systemd/coredump.conf.d /var/log/journal
  printf '[Journal]\nStorage=persistent\nSystemMaxUse=500M\nMaxRetentionSec=3month\n' \
    > /etc/systemd/journald.conf.d/90-harden.conf
  systemd-tmpfiles --create --prefix /var/log/journal >/dev/null 2>&1 || true
  systemctl restart systemd-journald || true
  printf '[Coredump]\nStorage=none\nProcessSizeMax=0\n' > /etc/systemd/coredump.conf.d/90-harden.conf
  printf '* hard core 0\nroot hard core 0\n' > /etc/security/limits.d/90-harden-nocore.conf
  ok "journald persistent (500M / 3 мес.), core dumps выключены"
}

setup_auto_updates() {
  [[ $AUTO_UPDATES == yes ]] || return 0
  step "Автообновления безопасности"
  cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
  local reboot=false; if [[ $AUTO_REBOOT == yes ]]; then reboot=true; fi
  cat > /etc/apt/apt.conf.d/52harden-unattended <<EOF
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "$reboot";
Unattended-Upgrade::Automatic-Reboot-Time "$AUTO_REBOOT_TIME";
EOF
  systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
  ok "unattended-upgrades (только security), авто-reboot: $reboot"
}

write_rollback() {
  cat > "$STATE_DIR/rollback.sh" <<EOF
#!/bin/bash
# Автооткат harden.sh ($TS): восстанавливает SSH и firewall из бэкапа
exec >>"$STATE_DIR/rollback.log" 2>&1
echo "=== rollback \$(date -Is) ==="
systemctl stop $RB_UNIT.timer 2>/dev/null
B="$BACKUP_DIR"
if [ -d "\$B/ssh" ]; then
  rm -rf /etc/ssh.rb && cp -a "\$B/ssh" /etc/ssh.rb && rm -rf /etc/ssh && mv /etc/ssh.rb /etc/ssh
fi
if command -v ufw >/dev/null 2>&1; then
  if [ "$UFW_WAS_ACTIVE" = yes ] && [ -d "\$B/ufw" ]; then
    rm -rf /etc/ufw && cp -a "\$B/ufw" /etc/ufw && ufw reload
  else
    ufw --force disable
  fi
fi
systemctl stop fail2ban 2>/dev/null
mkdir -p /run/sshd
systemctl restart ssh.service || systemctl restart sshd.service
rm -f "$STATE_DIR/state"
logger -t harden "Откат SSH/firewall выполнен (бэкап \$B)"
echo "Откат выполнен"
EOF
  chmod 700 "$STATE_DIR/rollback.sh"
}

write_confirm() {
  local p spec dels="" lock=""
  if [[ $FIREWALL == yes ]]; then
    for p in "${OLD_PORTS[@]}"; do
      while IFS= read -r spec; do dels+="ufw --force delete $spec >/dev/null && echo '[✓] ufw: удалено $spec'"$'\n'; done < <(ssh_rule_specs "$p")
    done
  fi
  if [[ $LOCK_ROOT_PASSWORD == yes ]]; then
    lock="passwd -l root >/dev/null && echo '[✓] Пароль root заблокирован'"
  fi
  cat > "$STATE_DIR/confirm.sh" <<EOF
#!/bin/bash
# Подтверждение harden.sh ($TS): отменяет автооткат и закрывает старый порт SSH
if [ ! -f "$STATE_DIR/state" ]; then
  echo "Нечего подтверждать: уже подтверждено или был откат (см. $STATE_DIR/rollback.log)"; exit 1
fi
systemctl stop $RB_UNIT.timer 2>/dev/null; echo "[✓] Автооткат отменён"
if [ -f "$SSHD_TRANSITION" ]; then
  rm -f "$SSHD_TRANSITION"
  if sshd -t; then systemctl restart ssh.service && echo "[✓] sshd слушает только $SSH_PORT"
  else echo "[!] sshd -t: ошибка, проверь конфиг вручную"; fi
fi
$dels
$lock
rm -f "$STATE_DIR/state"
echo "[✓] Готово: ssh -p $SSH_PORT $ADMIN_USER@$(server_ip)"
EOF
  chmod 700 "$STATE_DIR/confirm.sh"
  date -Is > "$STATE_DIR/state"
}

schedule_rollback() {
  systemctl stop "$RB_UNIT.timer" "$RB_UNIT.service" >/dev/null 2>&1 || true
  systemctl reset-failed "$RB_UNIT.service" >/dev/null 2>&1 || true
  systemd-run --quiet --unit="$RB_UNIT" --on-active="${ROLLBACK_MINUTES}min" \
    --timer-property=AccuracySec=1s /bin/bash "$STATE_DIR/rollback.sh"
  ok "Автооткат запланирован через $ROLLBACK_MINUTES мин"
}

apply_ssh() {
  step "SSH: только ключи, порт $SSH_PORT"
  local f kex ciphers macs eff fwd_agent=no
  if [[ $SSH_AGENT_FORWARDING == yes ]]; then fwd_agent=yes; fi
  install -d -m 755 /etc/ssh/sshd_config.d /run/sshd

  if ! grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
    sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
  fi
  # Port — накопительная директива: комментируем её во всех чужих файлах
  for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
    if [[ ! -f $f || $f == "$SSHD_DROPIN" || $f == "$SSHD_TRANSITION" ]]; then continue; fi
    sed -i -E 's/^([[:space:]]*)(Port[[:space:]])/\1#harden# \2/I' "$f"
  done

  kex=$(filter_supported kex mlkem768x25519-sha256 sntrup761x25519-sha512 sntrup761x25519-sha512@openssh.com \
        curve25519-sha256 curve25519-sha256@libssh.org diffie-hellman-group18-sha512 \
        diffie-hellman-group16-sha512 diffie-hellman-group-exchange-sha256)
  ciphers=$(filter_supported cipher chacha20-poly1305@openssh.com aes256-gcm@openssh.com \
        aes128-gcm@openssh.com aes256-ctr aes192-ctr aes128-ctr)
  macs=$(filter_supported mac hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com umac-128-etm@openssh.com)

  {
    echo "# harden.sh $SCRIPT_VERSION — $(date -Is)"
    echo "# Файл читается первым, а в sshd побеждает ПЕРВОЕ значение (перебивает 50-cloud-init.conf)"
    echo "Port $SSH_PORT"
    cat <<EOF
PermitRootLogin $SSH_ROOT_LOGIN
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitEmptyPasswords no
HostbasedAuthentication no
IgnoreRhosts yes
UsePAM yes
AllowGroups $SSH_GROUP
MaxAuthTries 4
MaxSessions 10
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding $fwd_agent
AllowTcpForwarding $SSH_TCP_FORWARDING
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no
PermitUserEnvironment no
Compression no
UseDNS no
LogLevel VERBOSE
EOF
    if [[ -n $kex ]];     then echo "KexAlgorithms $kex"; fi
    if [[ -n $ciphers ]]; then echo "Ciphers $ciphers"; fi
    if [[ -n $macs ]];    then echo "MACs $macs"; fi
  } > "$SSHD_DROPIN"
  chmod 644 "$SSHD_DROPIN"

  rm -f "$SSHD_TRANSITION"
  if [[ ${#OLD_PORTS[@]} -gt 0 ]]; then
    { echo "# Временный: старый порт до подтверждения (harden.sh --confirm)"; printf 'Port %s\n' "${OLD_PORTS[@]}"; } > "$SSHD_TRANSITION"
  fi

  if [[ -f /etc/ssh/moduli ]]; then
    awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.harden
    if [[ -s /etc/ssh/moduli.harden ]]; then mv /etc/ssh/moduli.harden /etc/ssh/moduli; else rm -f /etc/ssh/moduli.harden; fi
  fi

  if ! sshd -t; then restore_ssh; die "sshd -t: ошибка конфигурации — /etc/ssh восстановлен из бэкапа"; fi
  eff=$(sshd -T 2>/dev/null)
  if ! grep -qx 'passwordauthentication no' <<<"$eff" || ! grep -qx "port $SSH_PORT" <<<"$eff" \
     || grep -qx 'permitrootlogin yes' <<<"$eff"; then
    restore_ssh; die "Итоговый конфиг sshd не совпал с ожидаемым (Include не в начале?) — откатил"
  fi
  ok "Конфиг проверен (sshd -t / sshd -T)"

  # Ubuntu 22.10+: socket activation игнорирует Port без daemon-reload → переводим на ssh.service
  if [[ $(systemctl is-enabled ssh.socket 2>/dev/null || true) == enabled ]] || systemctl is-active --quiet ssh.socket 2>/dev/null; then
    info "ssh.socket → обычный ssh.service"
    systemctl disable --now ssh.socket >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/ssh.service.d/00-socket.conf /etc/systemd/system/ssh.socket.d/addresses.conf
    systemctl daemon-reload
    systemctl enable ssh.service >/dev/null 2>&1
  fi
  systemctl restart ssh.service
  sleep 1
  if ! systemctl is-active --quiet ssh.service; then
    bash "$STATE_DIR/rollback.sh"; die "sshd не запустился — выполнен откат"
  fi
  local p
  for p in "$SSH_PORT" "${OLD_PORTS[@]}"; do
    if ss -Hltn "sport = :$p" | grep -q .; then ok "sshd слушает :$p"; else warn "sshd НЕ слушает :$p"; fi
  done
}

apply_firewall() {
  [[ $FIREWALL == yes ]] || return 0
  step "Firewall (UFW)"
  if [[ -f /etc/default/ufw ]]; then sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw; fi
  ufw default deny incoming >/dev/null
  ufw default allow outgoing >/dev/null
  local p spec
  for p in "$SSH_PORT" "${OLD_PORTS[@]}"; do
    while IFS= read -r spec; do
      # shellcheck disable=SC2086
      ufw $spec >/dev/null
    done < <(ssh_rule_specs "$p")
  done
  for p in $OPEN_PORTS; do ufw allow "$p" >/dev/null; ok "Открыт $p"; done
  ufw logging low >/dev/null
  ufw --force enable >/dev/null
  ok "UFW включён: входящие запрещены, кроме SSH${OPEN_PORTS:+ и $OPEN_PORTS}"
}

apply_fail2ban() {
  [[ $FAIL2BAN == yes ]] || return 0
  step "fail2ban"
  local -a all=("$SSH_PORT" "${OLD_PORTS[@]}"); local ports
  ports=$(IFS=,; echo "${all[*]}")
  cat > /etc/fail2ban/jail.d/zz-harden.local <<EOF
# harden.sh
[DEFAULT]
backend = systemd
banaction = nftables-multiport
banaction_allports = nftables-allports
bantime = 1h
bantime.increment = true
bantime.maxtime = 1w
findtime = 10m
maxretry = 4
ignoreip = 127.0.0.1/8 ::1 $TRUSTED_IPS

[sshd]
enabled = true
mode = aggressive
port = $ports
EOF
  if ! fail2ban-client -t >/dev/null 2>&1; then warn "fail2ban: ошибка конфига (fail2ban-client -t)"; return 0; fi
  systemctl enable fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban
  sleep 2
  if fail2ban-client status sshd >/dev/null 2>&1; then ok "jail sshd активен (бан 1ч → до 1 недели при повторах)"
  else warn "jail sshd не поднялся: journalctl -u fail2ban"; fi
}

report() {
  step "Итог"
  if [[ $FIREWALL == yes ]]; then ufw status verbose | sed 's/^/    /' || true; fi
  info "Слушающие порты:"; ss -ltnup | sed 's/^/    /' || true
  if [[ -f /var/run/reboot-required ]]; then warn "Нужна перезагрузка (ядро/библиотеки) — после подтверждения: sudo reboot"; fi
  info "Лог: $LOG   Бэкап: $BACKUP_DIR"
  if [[ -n $GENERATED_PW ]]; then
    if [[ $TTY_OK == yes ]]; then
      sleep 0.3
      printf '\n  %sПароль %s (для sudo и консоли провайдера) — сохрани в менеджер паролей:%s\n      %s\n\n' \
        "$CY" "$ADMIN_USER" "$CN" "$GENERATED_PW" >/dev/tty
      info "Пароль показан только на экране, в лог не записан"
    else
      (umask 077; printf '%s\n' "$GENERATED_PW" > "$STATE_DIR/$ADMIN_USER.password")
      warn "Пароль сохранён в $STATE_DIR/$ADMIN_USER.password — забери и удали файл"
    fi
  fi
}

confirm_flow() {
  step "ПРОВЕРКА ДОСТУПА — это окно не закрывай"
  cat <<EOF
    В НОВОМ окне терминала:
        ssh -p $SSH_PORT $ADMIN_USER@$(server_ip)
        sudo -v
    Без подтверждения через $ROLLBACK_MINUTES мин. SSH и firewall откатятся автоматически.
EOF
  if [[ $HAS_TTY == yes ]]; then
    local ans=""
    read -r -t $(( ROLLBACK_MINUTES * 60 - 15 )) -p "Вход по ключу работает? yes = подтвердить / no = откатить сейчас: " ans </dev/tty || true
    echo
    case ${ans,,} in
      yes|y|да|д) bash "$STATE_DIR/confirm.sh" ;;
      no|n|нет|н) bash "$STATE_DIR/rollback.sh"; die "SSH и firewall откатаны. Пользователь, обновления, sysctl остались." ;;
      *) warn "Ответа нет — сработает автооткат. Отменить: bash $STATE_DIR/confirm.sh" ;;
    esac
  else
    warn "После проверки входа выполни на сервере:  sudo bash $STATE_DIR/confirm.sh"
  fi
}

main() {
  info "harden.sh v$SCRIPT_VERSION — лог: $LOG"
  preflight
  gather_input
  install_base
  detect_ssh
  resolve_keys
  show_plan
  backup_configs
  system_upgrade
  install_packages
  setup_system
  setup_admin
  setup_sudo
  setup_sysctl
  setup_logging
  setup_auto_updates
  write_rollback
  write_confirm
  schedule_rollback
  apply_ssh
  apply_firewall
  apply_fail2ban
  report
  confirm_flow
}

main