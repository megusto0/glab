from __future__ import annotations

import gzip
import io
import hashlib
import logging
import math
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional, Tuple

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

from channel import (
    bsc_channel,
    bit_error_statistics,
    bytes_to_gray_png,
    repetition3_decode,
    repetition3_encode,
)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = STATIC_DIR / "uploads"

AES_KEY = b"0123456789ABCDEF0123456789ABCDEF"  # 32 байта для AES-256

LOG_HISTORY: List[Dict[str, str]] = []
UPLOAD_RECORDS: List[Dict[str, object]] = []
DATA_LOCK = Lock()

_FONT_CACHE: Dict[int, ImageFont.ImageFont] = {}


def get_font(size: int) -> ImageFont.ImageFont:
    """Return a font that supports кириллицу, с запасным вариантом."""
    if size not in _FONT_CACHE:
        try:
            _FONT_CACHE[size] = ImageFont.truetype("DejaVuSans.ttf", size)
        except OSError:
            _FONT_CACHE[size] = ImageFont.load_default()
    return _FONT_CACHE[size]


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
    font = get_font(14)
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


def format_size(value: Optional[int]) -> str:
    """Форматирует размер в байтах в удобном виде."""
    if value is None:
        return "—"
    units = ["Б", "КБ", "МБ", "ГБ"]
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "Б":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{value} Б"


def parse_bool(value: str | None) -> bool:
    """Утилита для безопасного разбора булевых флагов из формы."""
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def build_preview_image(header_lines: List[str], stages: List[Dict[str, object]]) -> Image.Image:
    """Собирает композитное превью из произвольных этапов."""
    tile_size = (300, 220)
    margin = 24
    caption_height = 72
    header_height = 52 + max(0, len(header_lines) - 1) * 18
    canvas_width = margin + len(stages) * (tile_size[0] + margin)
    canvas_height = margin + header_height + tile_size[1] + caption_height + margin
    canvas = Image.new("RGB", (canvas_width, canvas_height), (233, 236, 239))
    draw = ImageDraw.Draw(canvas)

    header_font = get_font(16)
    body_font = get_font(13)
    small_font = get_font(12)

    header_y = margin
    for index, line in enumerate(header_lines):
        draw.text(
            (margin, header_y),
            line,
            font=header_font if index == 0 else body_font,
            fill=(33, 37, 41) if index == 0 else (73, 80, 87),
        )
        header_y += 18

    for index, stage in enumerate(stages):
        title = stage.get("title", f"Этап {index + 1}")
        subtitle_lines: List[str] = stage.get("lines", [])
        image_obj = stage.get("image")

        stage_image: Optional[Image.Image] = None
        if isinstance(image_obj, Image.Image):
            stage_image = image_obj.convert("RGB")
        elif isinstance(image_obj, bytes):
            stage_image = load_image_from_bytes(image_obj)
        if stage_image is None:
            stage_image = create_placeholder_image("Нет визуализации", tile_size)

        prepared = prepare_tile(stage_image, tile_size)
        x_offset = margin + index * (tile_size[0] + margin)
        y_offset = margin + header_height
        canvas.paste(prepared, (x_offset, y_offset))
        draw.rectangle(
            [x_offset - 1, y_offset - 1, x_offset + tile_size[0] + 1, y_offset + tile_size[1] + 1],
            outline=(173, 181, 189),
            width=1,
        )

        text_y = y_offset + tile_size[1] + 10
        draw.text((x_offset, text_y), title, font=body_font, fill=(33, 37, 41))
        text_y += 16
        for line in subtitle_lines:
            draw.text((x_offset, text_y), line, font=small_font, fill=(73, 80, 87))
            text_y += 14

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

    use_encryption = parse_bool(request.form.get("use_encryption"))
    use_compression = parse_bool(request.form.get("use_compression"))
    convert_to_bmp = parse_bool(request.form.get("convert_to_bmp"))
    ecc_mode = request.form.get("ecc_mode", "none").strip().lower()
    if ecc_mode not in {"none", "rep3"}:
        ecc_mode = "none"
    integrity_mode = request.form.get("integrity_mode", "off").strip().lower()
    if integrity_mode not in {"off", "hash_open", "hash_cipher"}:
        integrity_mode = "off"

    try:
        channel_ber = float(request.form.get("channel_ber", "0"))
    except ValueError:
        channel_ber = 0.0
    channel_ber = max(0.0, min(channel_ber, 0.5))

    try:
        channel_seed = int(request.form.get("channel_seed", "1"))
    except ValueError:
        channel_seed = 1

    original_name = file_storage.filename or "без имени"
    now = datetime.now()
    upload_id = now.strftime("%Y%m%d%H%M%S%f")
    timestamp_for_files = now.strftime("%Y%m%d_%H%M%S_%f")
    readable_timestamp = now.strftime("%Y-%m-%d %H:%M:%S")

    module_labels = []
    if use_encryption:
        module_labels.append("🔒 шифрование")
    if use_compression:
        module_labels.append("📦 GZIP")
    if ecc_mode != "none":
        module_labels.append("🛡 ПОК (повтор 3×)")
    if integrity_mode != "off":
        module_labels.append(f"✅ контроль: {integrity_mode}")
    if channel_ber > 0:
        module_labels.append(f"📡 канал BER={channel_ber:.2%}")
    if convert_to_bmp:
        module_labels.append("🖼 BMP-копия перед GZIP")
    modules_text = ", ".join(module_labels) if module_labels else "модули отключены"

    add_log(f"📥 Получен файл: {original_name}", upload_id=upload_id)
    add_log(f"⚙ Выбор модулей: {modules_text}", upload_id=upload_id)
    add_log(f"📡 Параметры канала: BER={channel_ber:.4f}, seed={channel_seed}", upload_id=upload_id)

    try:
        raw_bytes = file_storage.read()
        original_size = len(raw_bytes)
        add_log(f"📏 Исходный размер: {original_size} байт", upload_id=upload_id)

        record: Dict[str, object] = {
            "id": upload_id,
            "timestamp": readable_timestamp,
            "original_name": original_name,
            "status": "processing",
            "status_message": "",
            "modules": {
                "encryption": use_encryption,
                "compression": use_compression,
                "integrity": integrity_mode != "off",
                "integrity_mode": integrity_mode,
                "ecc": ecc_mode != "none",
                "ecc_mode": ecc_mode,
                "channel": channel_ber > 0,
                "convert_to_bmp": convert_to_bmp,
            },
            "sizes": {
                "original": original_size,
                "after_conversion": None,
                "after_compression": None,
                "after_ecc": None,
                "ciphertext": None,
                "after_channel": None,
                "after_decryption": None,
                "after_ecc_decode": None,
                "final": None,
            },
            "metrics": {
                "compression": None,
                "channel": None,
                "ecc": None,
                "integrity": {"mode": integrity_mode, "status": "off"},
            },
            "files": {},
            "channel": {"ber": channel_ber, "seed": channel_seed},
            "formats": {"original": Path(original_name).suffix or "", "final": ""},
        }

        def finalize_upload(
            status: str,
            status_message: str,
            http_status: int,
            payload: Dict[str, object],
        ):
            record["status"] = status
            record["status_message"] = status_message
            with DATA_LOCK:
                UPLOAD_RECORDS.append(record)
            add_log("📡 Обновления готовы для панели управления.", upload_id=upload_id)
            return jsonify(payload), http_status

        def fail_upload(
            log_message: str,
            client_message: str,
            status_message: Optional[str] = None,
            http_status: int = 400,
        ):
            add_log(log_message, level="ERROR", upload_id=upload_id)
            return finalize_upload(
                status="error",
                status_message=status_message or client_message,
                http_status=http_status,
                payload={"status": "error", "message": client_message},
            )

        # Сбор дополнительных сведений об исходном изображении
        original_format = "не определен"
        try:
            with Image.open(io.BytesIO(raw_bytes)) as original_info:
                original_format = original_info.format or original_format
        except Exception:  # noqa: BLE001
            pass
        record["formats"]["original"] = original_format

        # Этап 1. Опциональное перекодирование в BMP/PPM для демонстрации сжатия
        pre_compress_bytes = raw_bytes
        if convert_to_bmp:
            image_obj = load_image_from_bytes(raw_bytes)
            if image_obj:
                buffer = io.BytesIO()
                image_obj.save(buffer, format="BMP")
                pre_compress_bytes = buffer.getvalue()
                bmp_size = len(pre_compress_bytes)
                record["sizes"]["after_conversion"] = bmp_size
                record["formats"]["final"] = ".bmp"
                add_log(
                    f"🖼 Перекодировано в BMP перед сжатием: {bmp_size} байт",
                    upload_id=upload_id,
                )
            else:
                add_log(
                    "⚠️ Не удалось перекодировать файл в BMP, используется исходный поток.",
                    level="WARNING",
                    upload_id=upload_id,
                )
                record["modules"]["convert_to_bmp"] = False
                record["formats"]["final"] = ""

        # Этап 2. Сжатие GZIP (если выбрано)
        compressed_bytes = pre_compress_bytes
        compression_metrics: Optional[Dict[str, object]] = None
        if use_compression:
            compressed_bytes = gzip.compress(pre_compress_bytes)
            compressed_size = len(compressed_bytes)
            record["sizes"]["after_compression"] = compressed_size
            ratio_percent = (compressed_size / len(pre_compress_bytes) * 100) if pre_compress_bytes else 100.0
            savings_percent = 100.0 - ratio_percent
            change_bytes = compressed_size - len(pre_compress_bytes)
            compression_metrics = {
                "input": len(pre_compress_bytes),
                "output": compressed_size,
                "ratio_percent": ratio_percent,
                "savings_percent": savings_percent,
                "change_bytes": change_bytes,
            }
            record["metrics"]["compression"] = compression_metrics
            add_log(
                f"🗜 GZIP: {compressed_size} байт • Коэффициент: {ratio_percent:.1f}% "
                f"({change_bytes:+} Б, {'экономия' if savings_percent >= 0 else 'рост'} {abs(savings_percent):.1f}%)",
                upload_id=upload_id,
            )

        # Этап 3. Кодирование ПОК (повтор 3×) при необходимости
        plain_before_encryption = compressed_bytes
        ecc_metrics: Optional[Dict[str, object]] = None
        if ecc_mode == "rep3":
            encoded_bytes = repetition3_encode(compressed_bytes)
            record["sizes"]["after_ecc"] = len(encoded_bytes)
            overhead_percent = (len(encoded_bytes) / len(compressed_bytes) * 100) if compressed_bytes else 0.0
            add_log(
                f"🛡️ ПОК (повтор 3×): длина {len(encoded_bytes)} байт, накладные расходы {overhead_percent:.1f}%.",
                upload_id=upload_id,
            )
            plain_before_encryption = encoded_bytes
            ecc_metrics = {"mode": "rep3", "encoded_size": len(encoded_bytes), "overhead_percent": overhead_percent}
        record["metrics"]["ecc"] = ecc_metrics

        # Этап 4. Контроль целостности (sha) - эталон
        integrity_report = {"mode": integrity_mode, "status": "off"}
        hash_open_reference = None
        hash_cipher_reference = None
        if integrity_mode == "hash_open":
            hash_open_reference = hashlib.sha256(plain_before_encryption).hexdigest()
            integrity_report["status"] = "pending"
            add_log("🔍 Контроль (hash_open): вычислен SHA-256 по открытому потоку.", upload_id=upload_id)
        elif integrity_mode == "hash_cipher":
            integrity_report["status"] = "pending"

        # Этап 5. Шифрование
        ciphertext = plain_before_encryption
        if use_encryption:
            iv = get_random_bytes(AES.block_size)
            cipher_enc = AES.new(AES_KEY, AES.MODE_CBC, iv=iv)
            padded = pad(plain_before_encryption, AES.block_size)
            encrypted_bytes = cipher_enc.encrypt(padded)
            ciphertext = iv + encrypted_bytes
            add_log(
                f"🔒 AES-CBC: пакет длиной {len(ciphertext)} байт (включая IV).",
                upload_id=upload_id,
            )
        else:
            add_log("ℹ️ Шифрование отключено, данные отправлены в открытом виде.", upload_id=upload_id)
        record["sizes"]["ciphertext"] = len(ciphertext)
        if integrity_mode == "hash_cipher":
            hash_cipher_reference = hashlib.sha256(ciphertext).hexdigest()
            add_log("🔍 Контроль (hash_cipher): вычислен SHA-256 по шифртексту.", upload_id=upload_id)

        # Визуализация шифртекста
        cipher_png_bytes = bytes_to_gray_png(ciphertext)

        # Этап 6. Канал с ошибками
        channel_bytes = bsc_channel(ciphertext, channel_ber, seed=channel_seed)
        record["sizes"]["after_channel"] = len(channel_bytes)
        channel_stats = bit_error_statistics(ciphertext, channel_bytes)
        channel_stats.update({"ber_requested": channel_ber, "seed": channel_seed})
        record["metrics"]["channel"] = channel_stats
        bit_errors = channel_stats["bit_errors"]
        ber_actual = channel_stats["ber_actual"]
        if channel_ber > 0:
            add_log(
                f"📡 Канал BSC: битовых ошибок {bit_errors} (BER фактический {ber_actual:.4f}).",
                upload_id=upload_id,
            )
        else:
            add_log("📡 Канал без искажений (BER=0).", upload_id=upload_id)
        channel_png_bytes = bytes_to_gray_png(channel_bytes)

        # Контроль целостности по шифртексту
        if integrity_mode == "hash_cipher":
            hash_cipher_actual = hashlib.sha256(channel_bytes).hexdigest()
            if hash_cipher_actual == hash_cipher_reference:
                add_log("✅ Контроль hash_cipher: совпадает.", upload_id=upload_id)
                integrity_report = {"mode": integrity_mode, "status": "ok"}
            else:
                add_log("❌ Контроль hash_cipher: расхождение хэша.", level="WARNING", upload_id=upload_id)
                integrity_report = {"mode": integrity_mode, "status": "fail", "expected": hash_cipher_reference}

        # Этап 7. Расшифровка
        decrypted_plain = channel_bytes
        if use_encryption:
            add_log("🔓 Расшифровка AES-CBC.", upload_id=upload_id)
            iv = channel_bytes[: AES.block_size]
            encrypted_part = channel_bytes[AES.block_size :]
            try:
                cipher_dec = AES.new(AES_KEY, AES.MODE_CBC, iv=iv)
                decrypted_padded = cipher_dec.decrypt(encrypted_part)
                decrypted_plain = unpad(decrypted_padded, AES.block_size)
                add_log("✅ Расшифровка успешна.", upload_id=upload_id)
            except ValueError as exc:
                return fail_upload(
                    f"❌ Ошибка расшифровки AES: {exc}",
                    "Не удалось расшифровать данные",
                )
        record["sizes"]["after_decryption"] = len(decrypted_plain)

        # Этап 8. Декодирование ПОК
        after_ecc_decode = decrypted_plain
        if ecc_mode == "rep3":
            try:
                errors_before = bit_error_statistics(
                    compressed_bytes, decrypted_plain[: len(compressed_bytes)]
                )["bit_errors"]
            except Exception:  # noqa: BLE001
                errors_before = None
            try:
                after_ecc_decode = repetition3_decode(decrypted_plain)
            except ValueError as exc:
                return fail_upload(
                    f"❌ Ошибка декодирования ПОК: {exc}",
                    "Не удалось восстановить данные после канала",
                )
            record["sizes"]["after_ecc_decode"] = len(after_ecc_decode)
            errors_after = bit_error_statistics(compressed_bytes, after_ecc_decode)["bit_errors"]
            corrected = None
            if errors_before is not None:
                corrected = max(errors_before - errors_after, 0)
                add_log(
                    f"🛡️ ПОК: до декодирования {errors_before} бит-ошибок, после {errors_after}, исправлено ≈ {corrected}.",
                    upload_id=upload_id,
                )
            else:
                add_log(
                    f"🛡️ ПОК восстановил поток, остатков ошибок {errors_after}.",
                    upload_id=upload_id,
                )
            record["metrics"]["ecc"] = {
                "mode": "rep3",
                "errors_before": errors_before,
                "errors_after": errors_after,
                "corrected": corrected,
            }

        # Этап 9. Распаковка GZIP
        final_bytes = after_ecc_decode
        if use_compression:
            add_log("🗜 Распаковка GZIP.", upload_id=upload_id)
            try:
                final_bytes = gzip.decompress(after_ecc_decode)
                add_log("✅ Распаковка завершена.", upload_id=upload_id)
            except OSError as exc:
                return fail_upload(
                    f"❌ Ошибка распаковки GZIP: {exc}",
                    "Не удалось распаковать данные",
                )

        final_size = len(final_bytes)
        record["sizes"]["final"] = final_size

        # Контроль целостности по открытому потоку
        if integrity_mode == "hash_open":
            hash_open_actual = hashlib.sha256(after_ecc_decode).hexdigest()
            if hash_open_actual == hash_open_reference:
                add_log("✅ Контроль hash_open: совпадает.", upload_id=upload_id)
                integrity_report = {"mode": integrity_mode, "status": "ok"}
            else:
                add_log("❌ Контроль hash_open: обнаружено расхождение.", level="WARNING", upload_id=upload_id)
                integrity_report = {"mode": integrity_mode, "status": "fail"}
        record["metrics"]["integrity"] = integrity_report

        # Подготовка имени файлов и сохранение результатов
        safe_candidate = secure_filename(original_name)
        original_suffix = Path(original_name).suffix
        final_suffix = ".bmp" if record["formats"]["final"] else original_suffix or ".bin"
        if not safe_candidate:
            hash_suffix = hashlib.sha1(original_name.encode("utf-8", "ignore")).hexdigest()[:10]
            safe_candidate = f"upload_{hash_suffix}"
        safe_stem = Path(safe_candidate).stem or "file"
        final_filename = f"{timestamp_for_files}_{safe_stem}{final_suffix}"
        (UPLOAD_DIR / final_filename).write_bytes(final_bytes)
        add_log(f"💾 Файл сохранен как {final_filename}", upload_id=upload_id)
        record["files"]["final"] = final_filename
        record["formats"]["final"] = final_suffix

        cipher_preview_name = f"{timestamp_for_files}_cipher.png"
        (UPLOAD_DIR / cipher_preview_name).write_bytes(cipher_png_bytes)
        record["files"]["cipher_preview"] = cipher_preview_name

        channel_preview_name = f"{timestamp_for_files}_channel.png"
        (UPLOAD_DIR / channel_preview_name).write_bytes(channel_png_bytes)
        record["files"]["channel_preview"] = channel_preview_name

        # Композитное превью для dashboard
        header_lines = [
            f"{original_name} • {modules_text or 'модули отключены'}",
            f"BER: {channel_ber:.3%} | seed: {channel_seed} | ECC: {'rep3' if ecc_mode == 'rep3' else 'off'}",
            f"Время: {readable_timestamp}",
        ]

        stages: List[Dict[str, object]] = []
        stages.append(
            {
                "title": "Оригинал",
                "image": load_image_from_bytes(raw_bytes) or create_placeholder_image("Нет превью"),
                "lines": [
                    f"Размер: {format_size(original_size)}",
                    f"Формат: {original_format}",
                ],
            }
        )
        if record["sizes"]["after_conversion"]:
            stages.append(
                {
                    "title": "BMP перед GZIP",
                    "image": load_image_from_bytes(pre_compress_bytes),
                    "lines": [f"Размер: {format_size(record['sizes']['after_conversion'])}"],
                }
            )
        if use_compression:
            gzip_placeholder = create_placeholder_image("Поток GZIP\n(визуализация не\nподдерживается)")
            compression_line = f"{format_size(record['sizes']['after_compression'])}"
            if compression_metrics:
                compression_line += f" • {compression_metrics['ratio_percent']:.1f}%"
            stages.append(
                {
                    "title": "После сжатия",
                    "image": gzip_placeholder,
                    "lines": [compression_line],
                }
            )

        with Image.open(io.BytesIO(cipher_png_bytes)) as cipher_image:
            cipher_visual = cipher_image.convert("RGB")
        stages.append(
            {
                "title": "Шифртекст",
                "image": cipher_visual,
                "lines": [
                    f"{format_size(record['sizes']['ciphertext'])}",
                    "Градация серого",
                ],
            }
        )

        with Image.open(io.BytesIO(channel_png_bytes)) as channel_image:
            channel_visual = channel_image.convert("RGB")
        stage_lines = [f"{format_size(record['sizes']['after_channel'])}"]
        if bit_errors:
            stage_lines.append(f"Ошибок: {bit_errors}")
        stages.append(
            {
                "title": "После канала",
                "image": channel_visual,
                "lines": stage_lines,
            }
        )

        final_image_obj = load_image_from_bytes(final_bytes) or create_placeholder_image("Получены данные")
        stages.append(
            {
                "title": "Итоговый файл",
                "image": final_image_obj,
                "lines": [
                    f"Размер: {format_size(final_size)}",
                    f"Формат: {Path(final_filename).suffix or '—'}",
                ],
            }
        )

        preview_image = build_preview_image(header_lines, stages)
        preview_name = f"{timestamp_for_files}_preview.png"
        preview_path = UPLOAD_DIR / preview_name
        preview_image.save(preview_path)
        record["files"]["preview"] = preview_name
        add_log(f"🖼 Сводное превью сохранено как {preview_name}", upload_id=upload_id)

        add_log("✅ Загрузка завершена успешно.", upload_id=upload_id)
        return finalize_upload(
            status="success",
            status_message="Файл успешно загружен",
            http_status=200,
            payload={"status": "success", "message": "Файл успешно загружен"},
        )
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
