from __future__ import annotations

import gzip
import io
import hashlib
import logging
import math
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Dict, List

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
from PIL import Image, ImageDraw, ImageFont


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = STATIC_DIR / "uploads"

AES_KEY = b"0123456789ABCDEF0123456789ABCDEF"  # 32 байта для AES-256

LOG_HISTORY: List[Dict[str, str]] = []
UPLOAD_RECORDS: List[Dict[str, object]] = []
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


def add_log(message: str, level: str = "INFO", upload_id: str | None = None) -> None:
    """Добавляет сообщение в общий лог и выводит его в консоль."""
    level_upper = level.upper()
    log_func = getattr(logging, level_upper.lower(), logging.info)
    log_func(message)
    entry = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "level": level_upper,
        "message": message,
    }
    if upload_id:
        entry["upload_id"] = upload_id
    with DATA_LOCK:
        LOG_HISTORY.append(entry)


def load_image_from_bytes(data: bytes) -> Image.Image | None:
    """Пытается загрузить изображение из набора байтов."""
    if not data:
        return None
    try:
        with Image.open(io.BytesIO(data)) as img:
            return img.convert("RGB")
    except Exception:  # noqa: BLE001
        return None


def create_placeholder_image(text: str, size: tuple[int, int] = (320, 240)) -> Image.Image:
    """Создает заглушку с текстом."""
    image = Image.new("RGB", size, (33, 37, 41))
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default()
    text_lines = text.split("\n")
    total_height = 0
    line_heights: List[int] = []
    line_widths: List[int] = []
    for line in text_lines:
        bbox = draw.textbbox((0, 0), line, font=font)
        height = bbox[3] - bbox[1]
        width = bbox[2] - bbox[0]
        line_heights.append(height)
        line_widths.append(width)
        total_height += height
    y_offset = (size[1] - total_height) // 2
    for index, line in enumerate(text_lines):
        line_width = line_widths[index]
        line_height = line_heights[index]
        x_offset = (size[0] - line_width) // 2
        draw.text((x_offset, y_offset), line, font=font, fill=(248, 249, 250))
        y_offset += line_height
    return image


def visualize_bytes_as_image(data: bytes, tile_size: tuple[int, int]) -> Image.Image:
    """Преобразует поток байтов в визуализацию для демонстрации."""
    if not data:
        return create_placeholder_image("Нет данных", tile_size)

    width = min(tile_size[0], 256)
    height = math.ceil(len(data) / width)
    padded_length = width * height
    padded = data + b"\x00" * (padded_length - len(data))
    try:
        noise = Image.frombytes("L", (width, height), padded)
    except ValueError:
        return create_placeholder_image("Невозможно визуализировать", tile_size)
    noise = noise.resize(tile_size, Image.NEAREST).convert("RGB")
    return noise


def prepare_tile(image: Image.Image, tile_size: tuple[int, int]) -> Image.Image:
    """Формирует плитку фиксированного размера с учетом пропорций исходного изображения."""
    tile = Image.new("RGB", tile_size, (248, 249, 250))
    if image.mode != "RGB":
        image = image.convert("RGB")
    img_copy = image.copy()
    img_copy.thumbnail((tile_size[0] - 12, tile_size[1] - 12), Image.LANCZOS)
    x = (tile_size[0] - img_copy.width) // 2
    y = (tile_size[1] - img_copy.height) // 2
    tile.paste(img_copy, (x, y))
    return tile


def build_preview_image(
    original_bytes: bytes,
    processed_bytes: bytes,
    final_bytes: bytes,
    modules_text: str,
    timestamp: str,
    original_name: str,
    original_size: int,
    processed_size: int,
    final_size: int,
    compression_info: Dict[str, object] | None,
) -> Image.Image:
    """Создает сводное изображение для панели управления."""
    tile_size = (320, 240)

    original_img = load_image_from_bytes(original_bytes) or create_placeholder_image("Не удалось\nпрочитать\nисходное\nизображение")
    final_img = load_image_from_bytes(final_bytes) or create_placeholder_image("Полученные\nданные\nне изображение")

    if modules_text == "нет":
        processed_img = original_img.copy()
    else:
        processed_img = visualize_bytes_as_image(processed_bytes, tile_size)

    tiles = [
        ("Клиент", original_img, original_size),
        ("Канальный поток", processed_img, processed_size),
        ("После сервера", final_img, final_size),
    ]

    prepared_tiles = [(title, prepare_tile(img, tile_size), size) for title, img, size in tiles]

    margin = 24
    header_height = 120
    canvas_width = tile_size[0] * 3 + margin * 4
    canvas_height = tile_size[1] + header_height + margin * 2 + 48
    canvas = Image.new("RGB", (canvas_width, canvas_height), (233, 236, 239))
    draw = ImageDraw.Draw(canvas)
    font = ImageFont.load_default()

    header_text = f"Модули: {modules_text} • Имя: {original_name or 'без имени'}"
    draw.text((margin, margin), header_text, font=font, fill=(33, 37, 41))
    subheader = (
        f"Исходный размер: {original_size} Б • После модулей: {processed_size} Б • На выходе: {final_size} Б"
    )
    draw.text((margin, margin + 18), subheader, font=font, fill=(73, 80, 87))
    compression_line = ""
    if compression_info and compression_info.get("method") == "gzip":
        stage_size = compression_info.get("stage_size")
        ratio_percent = compression_info.get("ratio_percent")
        change_bytes = compression_info.get("delta")
        savings_percent = compression_info.get("delta_percent")
        change_phrase = ""
        if isinstance(savings_percent, (int, float)):
            if savings_percent >= 0:
                change_phrase = f"экономия {savings_percent:.1f}%"
            else:
                change_phrase = f"рост {abs(savings_percent):.1f}%"
        if isinstance(stage_size, (int, float)) and isinstance(ratio_percent, (int, float)) and isinstance(change_bytes, (int, float)):
            compression_line = (
                f"GZIP: {int(stage_size)} Б • Коэффициент: {ratio_percent:.1f}% "
                f"({int(change_bytes):+} Б"
            )
            if change_phrase:
                compression_line += f", {change_phrase}"
            compression_line += ")"
        else:
            compression_line = "GZIP: статистика недоступна."
    elif modules_text == "нет":
        compression_line = "Модули не задействованы."
    else:
        compression_line = "GZIP отключен."
    draw.text((margin, margin + 36), compression_line, font=font, fill=(73, 80, 87))
    draw.text((margin, margin + 54), f"Время: {timestamp}", font=font, fill=(73, 80, 87))

    for index, (title, tile, size_bytes) in enumerate(prepared_tiles):
        x_offset = margin + index * (tile_size[0] + margin)
        y_offset = margin + header_height
        canvas.paste(tile, (x_offset, y_offset))
        draw.rectangle(
            [x_offset - 1, y_offset - 1, x_offset + tile_size[0] + 1, y_offset + tile_size[1] + 1],
            outline=(173, 181, 189),
            width=1,
        )
        caption = f"{title}\n{size_bytes} Б"
        draw.text((x_offset, y_offset + tile_size[1] + 8), caption, font=font, fill=(33, 37, 41))

    return canvas


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
        logs_copy = list(LOG_HISTORY)
        uploads_copy = list(UPLOAD_RECORDS)
    return jsonify({"logs": logs_copy, "uploads": uploads_copy})


@app.route("/upload", methods=["POST"])
def upload():
    """Обрабатывает загрузку изображений с демонстрацией модулей."""
    if "image" not in request.files:
        add_log("❌ Ошибка: не найден файл изображения в запросе.", level="ERROR")
        return jsonify({"status": "error", "message": "Файл изображения не найден"}), 400

    file_storage = request.files["image"]
    if file_storage.filename == "":
        add_log("❌ Ошибка: пустое имя файла.", level="ERROR")
        return jsonify({"status": "error", "message": "Имя файла пустое"}), 400

    use_encryption = request.form.get("use_encryption", "false").lower() == "true"
    use_compression = request.form.get("use_compression", "false").lower() == "true"
    use_integrity = request.form.get("use_integrity", "false").lower() == "true"
    integrity_hash = request.form.get("integrity_hash", "")

    original_name = file_storage.filename or "без имени"
    now = datetime.now()
    upload_id = now.strftime("%Y%m%d%H%M%S%f")
    timestamp_for_files = now.strftime("%Y%m%d_%H%M%S_%f")
    readable_timestamp = now.strftime("%Y-%m-%d %H:%M:%S")

    enabled_modules = []
    if use_encryption:
        enabled_modules.append("Шифрование")
    if use_compression:
        enabled_modules.append("Сжатие")
    if use_integrity:
        enabled_modules.append("Проверка целостности")
    modules_text = ", ".join(enabled_modules) if enabled_modules else "нет"

    add_log(f"📥 Получен файл: {original_name}", upload_id=upload_id)
    add_log(f"⚙ Включенные модули: {modules_text}", upload_id=upload_id)

    try:
        raw_bytes = file_storage.read()
        original_size = len(raw_bytes)
        add_log(f"📏 Исходный размер: {original_size} байт", upload_id=upload_id)

        record: Dict[str, object] = {
            "id": upload_id,
            "timestamp": readable_timestamp,
            "original_name": original_name,
            "modules": {
                "encryption": use_encryption,
                "compression": use_compression,
                "integrity": use_integrity,
            },
            "status": "processing",
            "status_message": "",
            "sizes": {
                "original": original_size,
                "after_compression": None,
                "after_encryption": None,
                "final": None,
                "compression_ratio_percent": None,
            },
            "files": {},
            "compression": None,
        }

        def finalize_upload(status: str, status_message: str, http_status: int, payload: Dict[str, object]):
            record["status"] = status
            record["status_message"] = status_message
            with DATA_LOCK:
                UPLOAD_RECORDS.append(record)
            add_log("📡 Обновления готовы для панели управления.", upload_id=upload_id)
            return jsonify(payload), http_status

        def fail_upload(message: str, client_message: str, http_status: int = 400):
            add_log(message, level="ERROR", upload_id=upload_id)
            return finalize_upload(
                status="error",
                status_message=message,
                http_status=http_status,
                payload={"status": "error", "message": client_message},
            )

        if use_integrity:
            if not integrity_hash:
                return fail_upload(
                    "❌ Ошибка: хэш не передан, хотя включена проверка целостности.",
                    "Не передан хэш для проверки целостности",
                )
            integrity_hash = integrity_hash.strip().lower()
            add_log("🔐 Получен контрольный хэш от клиента (SHA-256).", upload_id=upload_id)

        processed_bytes = raw_bytes
        compressed_size = None
        compression_details: Dict[str, object] | None = None
        if use_compression:
            processed_bytes = gzip.compress(processed_bytes)
            compressed_size = len(processed_bytes)
            record["sizes"]["after_compression"] = compressed_size
            ratio_percent = (compressed_size / original_size * 100) if original_size else 100.0
            savings_percent = (1 - compressed_size / original_size) * 100 if original_size else 0.0
            change_bytes = compressed_size - original_size
            savings_text = (
                f"экономия {savings_percent:.1f}%"
                if savings_percent >= 0
                else f"увеличение {abs(savings_percent):.1f}%"
            )
            record["sizes"]["compression_ratio_percent"] = ratio_percent
            compression_details = {
                "output_size": compressed_size,
                "ratio_percent": ratio_percent,
                "savings_percent": savings_percent,
                "change_bytes": change_bytes,
            }
            record["compression"] = compression_details
            add_log(
                f"🗜 Размер после GZIP: {compressed_size} байт • Коэффициент сжатия: {ratio_percent:.1f}% "
                f"({change_bytes:+} Б, {savings_text})",
                upload_id=upload_id,
            )

        channel_bytes = processed_bytes
        if use_encryption:
            iv = get_random_bytes(AES.block_size)
            cipher_enc = AES.new(AES_KEY, AES.MODE_CBC, iv=iv)
            padded = pad(channel_bytes, AES.block_size)
            encrypted_bytes = cipher_enc.encrypt(padded)
            channel_bytes = iv + encrypted_bytes
            record["sizes"]["after_encryption"] = len(channel_bytes)
            add_log(f"🔒 Данные зашифрованы (AES-CBC). Размер пакета: {len(channel_bytes)} байт", upload_id=upload_id)

        received_bytes = channel_bytes

        if use_encryption:
            add_log("🔓 Начинаю расшифровку данных.", upload_id=upload_id)
            iv = received_bytes[: AES.block_size]
            encrypted_part = received_bytes[AES.block_size :]
            try:
                cipher_dec = AES.new(AES_KEY, AES.MODE_CBC, iv=iv)
                decrypted_padded = cipher_dec.decrypt(encrypted_part)
                received_bytes = unpad(decrypted_padded, AES.block_size)
                add_log("✅ Расшифровка завершена успешно.", upload_id=upload_id)
            except ValueError as exc:
                return fail_upload(f"❌ Ошибка расшифровки: {exc}", "Не удалось расшифровать данные")

        if use_compression:
            add_log("🗜 Распаковка данных GZIP.", upload_id=upload_id)
            try:
                received_bytes = gzip.decompress(received_bytes)
                add_log("✅ Распаковка завершена успешно.", upload_id=upload_id)
            except OSError as exc:
                return fail_upload(f"❌ Ошибка распаковки: {exc}", "Не удалось распаковать данные")

        if use_integrity:
            add_log("🔍 Проверка целостности SHA-256.", upload_id=upload_id)
            computed_hash = hashlib.sha256(received_bytes).hexdigest()
            if computed_hash == integrity_hash:
                add_log("✅ Целостность данных подтверждена.", upload_id=upload_id)
            else:
                return fail_upload(
                    "❌ Целостность данных нарушена (SHA-256 не совпал).",
                    "Целостность данных нарушена",
                )

        safe_candidate = secure_filename(original_name)
        original_suffix = Path(original_name).suffix or Path(safe_candidate).suffix or ".bin"
        safe_candidate = secure_filename(original_name)
        if not safe_candidate:
            hash_suffix = hashlib.sha1(original_name.encode("utf-8", "ignore")).hexdigest()[:10]
            safe_candidate = f"upload_{hash_suffix}{original_suffix}"
        safe_path = Path(safe_candidate)
        safe_stem = safe_path.stem or "file"
        final_filename = f"{timestamp_for_files}_{safe_stem}{original_suffix}"
        save_path = UPLOAD_DIR / final_filename
        save_path.write_bytes(received_bytes)
        add_log(f"💾 Файл сохранен как {final_filename}", upload_id=upload_id)

        final_size = len(received_bytes)
        record["sizes"]["final"] = final_size
        record["status"] = "success"
        record["status_message"] = "Файл успешно загружен"

        preview_name = f"{timestamp_for_files}_preview.png"
        preview_path = UPLOAD_DIR / preview_name
        compression_info_payload = None
        if compression_details and compressed_size is not None:
            compression_info_payload = {
                "method": "gzip",
                "format": "GZIP",
                "output_suffix": original_suffix,
                "stage_size": compressed_size,
                "delta": compression_details["change_bytes"],
                "delta_percent": compression_details["savings_percent"],
                "ratio_percent": compression_details["ratio_percent"],
            }

        preview_image = build_preview_image(
            original_bytes=raw_bytes,
            processed_bytes=channel_bytes,
            final_bytes=received_bytes,
            modules_text=modules_text,
            timestamp=readable_timestamp,
            original_name=original_name,
            original_size=original_size,
            processed_size=len(channel_bytes),
            final_size=final_size,
            compression_info=compression_info_payload,
        )
        preview_image.save(preview_path)
        add_log(f"🖼 Превью обработанного потока сохранено как {preview_name}", upload_id=upload_id)

        record["files"] = {
            "preview": preview_name,
            "final": final_filename,
        }

        with DATA_LOCK:
            UPLOAD_RECORDS.append(record)

        add_log("✅ Загрузка завершена успешно.", upload_id=upload_id)
        add_log("📡 Обновления готовы для панели управления.", upload_id=upload_id)

        return jsonify({"status": "success", "message": "Файл успешно загружен"})
    except Exception as exc:  # noqa: BLE001
        logging.exception("Unexpected error during upload handling")
        add_log(f"❌ Непредвиденная ошибка обработки: {exc}", level="ERROR", upload_id=upload_id)
        return jsonify({"status": "error", "message": "Внутренняя ошибка сервера"}), 500


def main() -> None:
    """Точка входа для запуска сервера."""
    add_log("🚀 Сервер запущен на http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)


if __name__ == "__main__":
    main()
