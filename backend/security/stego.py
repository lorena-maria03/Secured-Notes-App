import base64
from PIL import Image
import io

def hide_message_in_image(image_bytes: bytes, message: str) -> bytes:
    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    pixels = list(img.getdata())

    binary_message = ''.join(format(ord(c), '08b') for c in message)
    binary_message += '1111111111111110'  # separator de final

    if len(binary_message) > len(pixels) * 3:
        raise ValueError("Message is too long for this image")

    new_pixels = []
    bit_index = 0

    for pixel in pixels:
        r, g, b = pixel
        if bit_index < len(binary_message):
            r = (r & 0xFE) | int(binary_message[bit_index])
            bit_index += 1
        if bit_index < len(binary_message):
            g = (g & 0xFE) | int(binary_message[bit_index])
            bit_index += 1
        if bit_index < len(binary_message):
            b = (b & 0xFE) | int(binary_message[bit_index])
            bit_index += 1
        new_pixels.append((r, g, b))

    new_img = Image.new("RGB", img.size)
    new_img.putdata(new_pixels)

    output = io.BytesIO()
    new_img.save(output, format="PNG")
    return output.getvalue()

def extract_message_from_image(image_bytes: bytes) -> str:
    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    pixels = list(img.getdata())

    bits = []
    for pixel in pixels:
        for channel in pixel:
            bits.append(str(channel & 1))

    chars = []
    for i in range(0, len(bits), 8):
        byte = ''.join(bits[i:i+8])
        if byte == '11111111':
            next_byte = ''.join(bits[i+8:i+16])
            if next_byte == '11111110':
                break
        chars.append(chr(int(byte, 2)))

    return ''.join(chars)