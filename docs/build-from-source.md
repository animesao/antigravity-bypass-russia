# Инструкция по сборке и установке из исходников

Полное руководство по сборке утилиты **Antigravity Bypass Russia** из исходного кода для всех поддерживаемых операционных систем: **Linux**, **macOS** и **Windows**.

---

## Содержание
- [Требования к окружению](#-общие-требования)
- [🐧 Linux (Ubuntu / Debian / Fedora / Arch)](#-linux)
  - [1. Системные зависимости](#1-системные-зависимости)
  - [2. Установка Rust](#2-установка-rust)
  - [3. Клонирование и сборка](#3-клонирование-и-сборка)
  - [4. Установка в систему](#4-установка-в-систему)
  - [5. Альтернативные способы (PKGBUILD / Скрипт)](#5-альтернативные-способы-linux)
- [🍏 macOS (Apple Silicon M1-M4 & Intel x86_64)](#-macos)
  - [1. Системные зависимости](#1-системные-зависимости-macos)
  - [2. Установка Rust](#2-установка-rust-macos)
  - [3. Клонирование и сборка](#3-клонирование-и-сборка-macos)
  - [4. Установка в систему](#4-установка-в-систему-macos)
  - [5. Сборка универсального бинарника (Universal Binary)](#5-универсальный-бинарник-macos)
- [🪟 Windows (10 / 11)](#-windows)
  - [1. Системные зависимости](#1-системные-зависимости-windows)
  - [2. Установка Rust](#2-установка-rust-windows)
  - [3. Клонирование и сборка](#3-клонирование-и-сборка-windows)
  - [4. Установка в систему (PowerShell)](#4-установка-в-систему-windows)
- [Проверка и запуск](#-проверка-и-запуск)

---

## 🛠 Общие требования

Для сборки проекта из исходников на любой платформе необходимы:
* **Git** — для получения репозитория.
* **Rust & Cargo** версии **1.89+** (требуется редакция Rust 2021).
* Компилятор C/C++ и сборочный инструментарий платформы.

---

## 🐧 Linux

Поддерживаются архитектуры **x86_64** и **aarch64 (ARM64)**.

### 1. Системные зависимости

Установите компилятор C, `pkg-config`, заголовочные файлы OpenSSL и Git:

* **Ubuntu / Debian / Linux Mint:**
  ```bash
  sudo apt update
  sudo apt install -y build-essential pkg-config libssl-dev git
  ```

* **Fedora / RHEL / CentOS:**
  ```bash
  sudo dnf install -y gcc pkgconf-pkg-config openssl-devel git
  ```

* **Arch Linux / Manjaro:**
  ```bash
  sudo pacman -S --needed base-devel openssl git
  ```

* **Alpine Linux:**
  ```bash
  apk add build-base pkgconfig openssl-dev git
  ```

### 2. Установка Rust

Если Rust еще не установлен:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

### 3. Клонирование и сборка

```bash
git clone https://github.com/animesao/antigravity-bypass-russia.git
cd antigravity-bypass-russia

# Сборка релизной версии
cargo build --release
```

> [!NOTE]
> Скомпилированный бинарный файл находится по пути: `target/release/antigravity-bypass-russia`.

### 4. Установка в систему

Скопируйте исполняемый файл в системный каталог `/usr/local/bin` и создайте удобный алиас:

```bash
sudo install -m 755 target/release/antigravity-bypass-russia /usr/local/bin/antigravity-bypass-russia
sudo ln -sf /usr/local/bin/antigravity-bypass-russia /usr/local/bin/ag-bypass
```

Теперь запуск доступен из любого терминала командой:
```bash
ag-bypass
```

### 5. Альтернативные способы (Linux)

* **Arch Linux через PKGBUILD:**
  ```bash
  cd packages/arch
  makepkg -si
  ```
* **Через встроенный скрипт автоматической сборки:**
  ```bash
  chmod +x scripts/unlock_and_restore.sh
  ./scripts/unlock_and_restore.sh
  ```
  *(Скрипт сам выполнит `cargo build --release` от имени текущего пользователя и запустит программу).*

---

## 🍏 macOS

Поддерживаются **Apple Silicon (M1/M2/M3/M4, arm64)** и **Intel (x86_64)**.

### 1. Системные зависимости (macOS)

Установите Command Line Tools от Apple (включает clang, git и сборочные утилиты):
```bash
xcode-select --install
```

### 2. Установка Rust (macOS)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

### 3. Клонирование и сборка (macOS)

```bash
git clone https://github.com/animesao/antigravity-bypass-russia.git
cd antigravity-bypass-russia

cargo build --release
```

Бинарный файл появится в `target/release/antigravity-bypass-russia`.

### 4. Установка в систему (macOS)

Установите бинарник в `/usr/local/bin` (на Intel) или `/opt/homebrew/bin` / `/usr/local/bin` (на Apple Silicon):

```bash
sudo install -m 755 target/release/antigravity-bypass-russia /usr/local/bin/antigravity-bypass-russia
sudo ln -sf /usr/local/bin/antigravity-bypass-russia /usr/local/bin/ag-bypass
```

Запуск:
```bash
ag-bypass
```

### 5. Универсальный бинарник (macOS)

Если требуется собрать один исполняемый файл, работающий и на Intel, и на Apple Silicon:

```bash
rustup target add x86_64-apple-darwin aarch64-apple-darwin

cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin

lipo -create -output target/release/antigravity-bypass-russia-universal \
  target/x86_64-apple-darwin/release/antigravity-bypass-russia \
  target/aarch64-apple-darwin/release/antigravity-bypass-russia

sudo install -m 755 target/release/antigravity-bypass-russia-universal /usr/local/bin/ag-bypass
```

---

## 🪟 Windows

Поддерживаются **Windows 10** и **Windows 11** (x86_64).

### 1. Системные зависимости (Windows)

Для сборки на Windows требуется компилятор MSVC C++:
* Установите **[Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)** (выберите компонент *"Разработка классических приложений на C++"* / *"Desktop development with C++"*).
* Либо установите через пакетный менеджер `winget`:
  ```powershell
  winget install Microsoft.VisualStudio.2022.BuildTools --override "--passive --add Microsoft.VisualStudio.Workload.VCTools"
  winget install Git.Git
  ```

### 2. Установка Rust (Windows)

1. Скачайте и запустите **[rustup-init.exe](https://rustup.rs/)** или выполните в PowerShell:
   ```powershell
   winget install Rustlang.Rustup
   ```
2. Перезапустите PowerShell и проверьте готовность:
   ```powershell
   cargo --version
   ```

### 3. Клонирование и сборка (Windows)

Откройте PowerShell:

```powershell
git clone https://github.com/animesao/antigravity-bypass-russia.git
cd antigravity-bypass-russia

# Сборка релизной версии
cargo build --release
```

> [!NOTE]
> При сборке под Windows `build.rs` автоматически встраивает иконку приложения (`assets/icon.ico`) и манипест выполнения.  
> Готовый исполняемый файл: `target\release\antigravity-bypass-russia.exe`.

### 4. Установка в систему (Windows)

Для удобного вызова из любой папки добавьте утилиту в системный каталог (например, `C:\Windows\System32` или каталог в переменной `$PATH`):

```powershell
# Запустите PowerShell от имени Администратора:
Copy-Item ".\target\release\antigravity-bypass-russia.exe" "C:\Windows\antigravity-bypass-russia.exe" -Force
Copy-Item ".\target\release\antigravity-bypass-russia.exe" "C:\Windows\ag-bypass.exe" -Force
```

Теперь команду можно вызывать в любом окне терминала (PowerShell / CMD / Terminal):
```powershell
ag-bypass
```

---

## 🚀 Проверка и запуск

После установки запустите утилиту:

* **Интерактивный режим (меню):**
  ```bash
  ag-bypass
  ```
  В появившемся меню введите **`1`** (**`Полная разблокировка`**) и нажмите **Enter**.

* **Прямые консольные команды:**
  ```bash
  # Применить разблокировку:
  ag-bypass unlock

  # Проверить статус:
  ag-bypass status

  # Запустить диагностику сети и Google AI:
  ag-bypass diagnostics

  # Полный откат (вернуть всё в исходное состояние):
  ag-bypass rollback
  ```
