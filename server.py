from __future__ import annotations

import gzip
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import List

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    send_from_directory,
)
from werkzeug.utils import secure_filename

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = STATIC_DIR / "uploads"

AES_KEY = b"0123456789ABCDEF0123456789ABCDEF"  # 32 байта для AES-256

LOG_MESSAGES: List[str] = []
IMAGE_NAMES: List[str] = []
DATA_LOCK = Lock()


def ensure_upload_dir() -> None:
    """Создает каталог загрузок, если он еще не существует."""
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def configure_logging() -> None:
    """Настраивает логирование приложения."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )


def add_log(message: str) -> None:
    """Добавляет сообщение в общий лог и выводит его в консоль."""
    logging.info(message)
    with DATA_LOCK:
        LOG_MESSAGES.append(message)


app = Flask(__name__, template_folder=str(BASE_DIR / "templates"), static_folder=str(STATIC_DIR))


configure_logging()
ensure_upload_dir()


@app.route("/")
def index() -> str:
    """Отдает страницу отправки изображения."""
    return render_template("index.html")


@app.route("/dashboard")
def dashboard() -> str:
    """Отдает панель управления сервером."""
    return render_template("dashboard.html")


@app.route("/uploads/<path:filename>")
def serve_uploaded_file(filename: str):
    """Отдает сохраненный файл по имени."""
    return send_from_directory(str(UPLOAD_DIR), filename)


@app.route("/get_updates")
def get_updates():
    """Возвращает логи и список изображений для панели управления."""
    with DATA_LOCK:
        logs_copy = list(LOG_MESSAGES)
        images_copy = list(IMAGE_NAMES)
    return jsonify({"logs": logs_copy, "images": images_copy})


@app.route("/upload", methods=["POST"])
def upload():
    """Обрабатывает загрузку изображений с демонстрацией модулей."""
    if "image" not in request.files:
        add_log("❌ Ошибка: не найден файл изображения в запросе.")
        return jsonify({"status": "error", "message": "Файл изображения не найден"}), 400

    file_storage = request.files["image"]
    if file_storage.filename == "":
        add_log("❌ Ошибка: пустое имя файла.")
        return jsonify({"status": "error", "message": "Имя файла пустое"}), 400

    use_encryption = request.form.get("use_encryption", "false").lower() == "true"
    use_compression = request.form.get("use_compression", "false").lower() == "true"
    use_integrity = request.form.get("use_integrity", "false").lower() == "true"
    integrity_hash = request.form.get("integrity_hash", "")

    original_name = secure_filename(file_storage.filename)
    add_log(f"📥 Получен файл: {original_name or 'неизвестно'}")

    enabled_modules = []
    if use_encryption:
        enabled_modules.append("Шифрование")
    if use_compression:
        enabled_modules.append("Сжатие")
    if use_integrity:
        enabled_modules.append("Проверка целостности")
    modules_text = ", ".join(enabled_modules) if enabled_modules else "нет"
    add_log(f"⚙ Включенные модули: {modules_text}")

    try:
        raw_bytes = file_storage.read()
        original_size = len(raw_bytes)
        add_log(f"📏 Исходный размер: {original_size} байт")

        processed_bytes = raw_bytes

        if use_integrity:
            add_log("🔐 Получен контрольный хэш от клиента (SHA-256).")
            if not integrity_hash:
                add_log("❌ Ошибка: хэш не передан, хотя включена проверка целостности.")
                return jsonify({"status": "error", "message": "Не передан хэш для проверки целостности"}), 400
            integrity_hash = integrity_hash.strip().lower()

        if use_compression:
            processed_bytes = gzip.compress(processed_bytes)
            add_log(f"🗜 Размер после сжатия: {len(processed_bytes)} байт")

        iv = b""
        if use_encryption:
            iv = get_random_bytes(AES.block_size)
            cipher_enc = AES.new(AES_KEY, AES.MODE_CBC, iv=iv)
            padded = pad(processed_bytes, AES.block_size)
            encrypted_bytes = cipher_enc.encrypt(padded)
            processed_bytes = iv + encrypted_bytes
            add_log(f"🔒 Данные зашифрованы (AES-CBC). Размер пакета: {len(processed_bytes)} байт")

        received_bytes = processed_bytes

        if use_encryption:
            add_log("🔓 Начинаю расшифровку данных.")
            iv = received_bytes[: AES.block_size]
            encrypted_part = received_bytes[AES.block_size :]
            try:
                cipher_dec = AES.new(AES_KEY, AES.MODE_CBC, iv=iv)
                decrypted_padded = cipher_dec.decrypt(encrypted_part)
                received_bytes = unpad(decrypted_padded, AES.block_size)
                add_log("✅ Расшифровка завершена успешно.")
            except ValueError as exc:
                add_log(f"❌ Ошибка расшифровки: {exc}")
                return jsonify({"status": "error", "message": "Не удалось расшифровать данные"}), 400

        if use_compression:
            add_log("🗜 Распаковка данных GZIP.")
            try:
                received_bytes = gzip.decompress(received_bytes)
                add_log("✅ Распаковка завершена успешно.")
            except OSError as exc:
                add_log(f"❌ Ошибка распаковки: {exc}")
                return jsonify({"status": "error", "message": "Не удалось распаковать данные"}), 400

        if use_integrity:
            add_log("🔍 Проверка целостности SHA-256.")
            computed_hash = hashlib.sha256(received_bytes).hexdigest()
            if computed_hash == integrity_hash:
                add_log("✅ Целостность данных подтверждена.")
            else:
                add_log("❌ ВНИМАНИЕ! Целостность данных нарушена!")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        suffix = Path(original_name).suffix or ".bin"
        saved_name = f"{timestamp}{suffix}"
        save_path = UPLOAD_DIR / saved_name
        save_path.write_bytes(received_bytes)
        add_log(f"💾 Файл сохранен как {saved_name}")

        if use_compression or use_encryption:
            processed_suffix = ".bin"
            if use_compression and not use_encryption:
                processed_suffix = suffix + ".gz"
            elif use_encryption:
                processed_suffix = ".enc"
            stored_processed_name = f"{timestamp}_processed{processed_suffix}"
            processed_save_path = UPLOAD_DIR / stored_processed_name
            processed_save_path.write_bytes(processed_bytes)
            add_log(
                f"💾 Обработанные данные сохранены как {stored_processed_name} "
                f"(размер: {len(processed_bytes)} байт)"
            )

        with DATA_LOCK:
            if saved_name not in IMAGE_NAMES:
                IMAGE_NAMES.append(saved_name)
        add_log("📡 Обновления готовы для панели управления.")

        return jsonify({"status": "success", "message": "Файл успешно загружен"})
    except Exception as exc:  # noqa: BLE001
        add_log(f"❌ Непредвиденная ошибка обработки: {exc}")
        return jsonify({"status": "error", "message": "Внутренняя ошибка сервера"}), 500


def main() -> None:
    """Точка входа для запуска сервера."""
    add_log("🚀 Сервер запущен на http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)


if __name__ == "__main__":
    main()
