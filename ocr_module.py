import os
from PIL import Image
_reader = None

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "bmp", "webp"}


def allowed_file(filename):
    """Check whether the uploaded file has an allowed image extension."""
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def _get_reader():
    """Lazily initialize and cache the EasyOCR reader (English)."""
    global _reader
    if _reader is None:
        import easyocr  
        _reader = easyocr.Reader(["en"], gpu=False)
    return _reader


def extract_text_from_image(image_path):
    """
    Extract text from an image file using EasyOCR.

    Args:
        image_path (str): path to the saved image file

    Returns:
        dict with:
            success (bool)
            text (str) - extracted text, empty string if none found
            error (str or None)
    """
    result = {"success": False, "text": "", "error": None}

    if not os.path.exists(image_path):
        result["error"] = "Uploaded image could not be found on the server."
        return result

    try:
        with Image.open(image_path) as img:
            img.verify()
    except Exception:
        result["error"] = "The uploaded file is not a valid image. Please upload a PNG or JPG screenshot."
        return result

    try:
        reader = _get_reader()
        ocr_output = reader.readtext(image_path, detail=0, paragraph=True)
        extracted_text = "\n".join(ocr_output).strip()

        if not extracted_text:
            result["error"] = "No readable text was found in the uploaded screenshot. Try a clearer image."
            return result

        result["success"] = True
        result["text"] = extracted_text
        return result

    except Exception as exc:
        result["error"] = f"OCR processing failed: {str(exc)}"
        return result
