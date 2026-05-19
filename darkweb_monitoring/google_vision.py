from .config import Settings
from .models import OCRResult


class VisionNotConfigured(RuntimeError):
    pass


def ocr_image_bytes(content: bytes, settings: Settings) -> OCRResult:
    if not settings.vision_ocr_enabled:
        raise VisionNotConfigured("Google Vision OCR is disabled. Set VISION_OCR_ENABLED=true.")
    if not settings.google_application_credentials:
        raise VisionNotConfigured("GOOGLE_APPLICATION_CREDENTIALS must point to a service account file.")

    from google.cloud import vision

    client = vision.ImageAnnotatorClient()
    image = vision.Image(content=content)
    response = client.document_text_detection(image=image)
    if response.error.message:
        raise RuntimeError(response.error.message)
    text = response.full_text_annotation.text if response.full_text_annotation else ""
    return OCRResult(text=text, pages_or_images=1, provider="google-cloud-vision")

