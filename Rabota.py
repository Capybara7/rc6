from PIL import Image
import base64
from units import *
from bitstring import BitArray

def image_to_bits(image_path):
    image = Image.open(image_path).convert('RGBA')
    image_data = image.tobytes()
    print(len(image_data))
    bits_img = ''.join(format(byte, '08b') for byte in image_data)
    return [image.mode, image.size, bits_img]

def bits_to_image(data, output_path):
    mode, size, bits = data
    bytes_array = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
    print(len(bytes_array))
    image = Image.frombytes(mode, size, bytes_array)
    image.save(output_path)
    return image

def bits_to_img_not_save(data):
    mode, size, bits = data
    bytes_array = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
    image = Image.frombytes(mode, size, bytes_array)
    return image

def key_to_bytes(key):
    return bytes(key, 'utf-8')