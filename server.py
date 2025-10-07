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

LOG_MESSAGES: List[str] = []
IMAGE_ENTRIES: List[Dict[str, object]] = []
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


def load_image_from_bytes(data: bytes) -> Image.Image | None:
    """Пытается загрузить изображение из набора байтов."""
    if not data:
        return None
    try:
        with Image.open(io.BytesIO(data)) as img:
            return img.convert("RGB")
    except Exception:  # noqa: BLE001
        return None


def open_image_for_compression(data: bytes) -> Image.Image | None:
    """Открывает изображение, сохраняя альфа-канал при необходимости."""
    if not data:
        return None
    try:
        with Image.open(io.BytesIO(data)) as img:
            mode = "RGBA" if "A" in img.mode else "RGB"
            return img.convert(mode)
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
    size_for_delta = processed_size
    if compression_info and isinstance(compression_info.get("stage_size"), (int, float)):
        try:
            size_for_delta = int(compression_info["stage_size"])
        except (TypeError, ValueError):
            size_for_delta = processed_size

    change_percent = 0.0
    if original_size:
        change_percent = (size_for_delta - original_size) / original_size * 100
    change_symbol = "−" if change_percent < 0 else "+"
    compression_details = ""
    if compression_info and compression_info.get("method") == "reencode":
        method_name = compression_info.get("format", "WebP")
        quality = compression_info.get("quality")
        if quality:
            compression_details = f"{method_name} q={quality}"
        else:
            compression_details = str(method_name)
    elif compression_info and compression_info.get("method") == "gzip":
        compression_details = "GZIP"

    subheader = (
        f"Исходный размер: {original_size} Б • После модулей: {processed_size} Б • На выходе: {final_size} Б"
    )
    draw.text((margin, margin + 18), subheader, font=font, fill=(73, 80, 87))
    delta_line = f"Δ потока: {change_symbol}{abs(change_percent):.1f}%"
    if compression_details:
        delta_line += f" ({compression_details})"
    draw.text((margin, margin + 36), delta_line, font=font, fill=(73, 80, 87))
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
        logs_copy = list(LOG_MESSAGES)
        images_copy = list(IMAGE_ENTRIES)
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
    original_suffix = Path(original_name).suffix or ".bin"
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
        stored_processed_name = ""
        processed_size = len(processed_bytes)
        compression_info: Dict[str, object] | None = None
        compressed_stage_size: int | None = None

        if use_integrity:
            add_log("🔐 Получен контрольный хэш от клиента (SHA-256).")
            if not integrity_hash:
                add_log("❌ Ошибка: хэш не передан, хотя включена проверка целостности.")
                return jsonify({"status": "error", "message": "Не передан хэш для проверки целостности"}), 400
            integrity_hash = integrity_hash.strip().lower()

        if use_compression:
            image_for_compression = open_image_for_compression(processed_bytes)
            if image_for_compression and not use_integrity:
                quality = 60
                buffer = io.BytesIO()
                image_for_compression.save(buffer, format="WEBP", quality=quality, method=6)
                processed_bytes = buffer.getvalue()
                processed_size = len(processed_bytes)
                delta = processed_size - original_size
                delta_percent = (delta / original_size) * 100 if original_size else 0.0
                compression_info = {
                    "method": "reencode",
                    "format": "WebP",
                    "quality": quality,
                    "output_suffix": ".webp",
                    "stage_size": processed_size,
                    "delta": delta,
                    "delta_percent": delta_percent,
                }
                add_log(
                    f"🗜 Перекодировано в WebP (качество {quality}). "
                    f"Размер: {processed_size} байт ({delta:+} Б, {delta_percent:+.1f}%)"
                )
                compressed_stage_size = processed_size
            else:
                processed_bytes = gzip.compress(processed_bytes)
                processed_size = len(processed_bytes)
                delta = processed_size - original_size
                delta_percent = (delta / original_size) * 100 if original_size else 0.0
                compression_info = {
                    "method": "gzip",
                    "format": "GZIP",
                    "output_suffix": original_suffix,
                    "stage_size": processed_size,
                    "delta": delta,
                    "delta_percent": delta_percent,
                }
                add_log(
                    f"🗜 Размер после сжатия GZIP: {processed_size} байт "
                    f"({delta:+} Б, {delta_percent:+.1f}%)"
                )
                if image_for_compression and use_integrity:
                    add_log("ℹ️ Проверка целостности требует без потерь, поэтому использован GZIP.")
                if not image_for_compression:
                    add_log("ℹ️ Файл не распознан как изображение, применяется GZIP.")
                compressed_stage_size = processed_size

        iv = b""
        if use_encryption:
            iv = get_random_bytes(AES.block_size)
            cipher_enc = AES.new(AES_KEY, AES.MODE_CBC, iv=iv)
            padded = pad(processed_bytes, AES.block_size)
            encrypted_bytes = cipher_enc.encrypt(padded)
            processed_bytes = iv + encrypted_bytes
            processed_size = len(processed_bytes)
            add_log(f"🔒 Данные зашифрованы (AES-CBC). Размер пакета: {processed_size} байт")

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
            if compression_info and compression_info.get("method") == "gzip":
                add_log("🗜 Распаковка данных GZIP.")
                try:
                    received_bytes = gzip.decompress(received_bytes)
                    add_log("✅ Распаковка завершена успешно.")
                except OSError as exc:
                    add_log(f"❌ Ошибка распаковки: {exc}")
                    return jsonify({"status": "error", "message": "Не удалось распаковать данные"}), 400
            else:
                add_log("🗜 Перекодированное изображение, распаковка не требуется.")

        if use_integrity:
            add_log("🔍 Проверка целостности SHA-256.")
            computed_hash = hashlib.sha256(received_bytes).hexdigest()
            if computed_hash == integrity_hash:
                add_log("✅ Целостность данных подтверждена.")
            else:
                add_log("❌ ВНИМАНИЕ! Целостность данных нарушена!")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        final_suffix = original_suffix
        if compression_info and compression_info.get("output_suffix"):
            final_suffix = str(compression_info["output_suffix"])
            if not final_suffix.startswith("."):
                final_suffix = f".{final_suffix}"
        saved_name = f"{timestamp}{final_suffix}"
        save_path = UPLOAD_DIR / saved_name
        save_path.write_bytes(received_bytes)
        add_log(f"💾 Файл сохранен как {saved_name}")

        final_size = len(received_bytes)

        should_store_processed = False
        processed_suffix = ".bin"
        if use_encryption:
            should_store_processed = True
            processed_suffix = ".enc"
        elif use_compression and compression_info and compression_info.get("method") == "gzip":
            should_store_processed = True
            processed_suffix = f"{original_suffix}.gz"

        if should_store_processed:
            stored_processed_name = f"{timestamp}_processed{processed_suffix}"
            processed_save_path = UPLOAD_DIR / stored_processed_name
            processed_save_path.write_bytes(processed_bytes)
            add_log(
                f"💾 Обработанные данные сохранены как {stored_processed_name} "
                f"(размер: {len(processed_bytes)} байт)"
            )

        preview_name = f"{timestamp}_preview.png"
        preview_path = UPLOAD_DIR / preview_name
        preview_image = build_preview_image(
            original_bytes=raw_bytes,
            processed_bytes=processed_bytes,
            final_bytes=received_bytes,
            modules_text=modules_text,
            timestamp=timestamp,
            original_name=original_name,
            original_size=original_size,
            processed_size=processed_size,
            final_size=final_size,
            compression_info=compression_info,
        )
        preview_image.save(preview_path)
        add_log(f"🖼 Превью обработанного потока сохранено как {preview_name}")

        entry = {
            "preview": preview_name,
            "final": saved_name,
            "processed": stored_processed_name,
            "modules": modules_text,
            "original_name": original_name,
            "timestamp": timestamp,
            "original_size": original_size,
            "processed_size": processed_size,
            "final_size": final_size,
            "compression_method": (compression_info or {}).get("method", "none"),
            "compression_format": (compression_info or {}).get("format", ""),
            "compression_quality": (compression_info or {}).get("quality"),
            "compression_stage_size": compressed_stage_size,
            "compression_delta": (compression_info or {}).get("delta"),
            "compression_delta_percent": (compression_info or {}).get("delta_percent"),
            "encryption_used": use_encryption,
            "integrity_used": use_integrity,
        }

        with DATA_LOCK:
            IMAGE_ENTRIES.append(entry)
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
