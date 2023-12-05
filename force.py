from PIL import Image
from math import sqrt, pow
from random import randint
from Rabota import *

def get_img_avg_brightness(image):
    result = .0
    count = image.width * image.height
    for y in range(image.height):
        for x in range(image.width):
            result += image.getpixel((x, y))
    return result/count


def calc_horizontal_covariation(image):
    result = .0
    average_brightness = get_img_avg_brightness(image)
    count = image.height * (image.width - 1)
    for y in range(image.height):   
        for x in range(image.width - 1):
            current_pixel = image.getpixel((x, y))
            neighbor_pixel = image.getpixel((x + 1, y))
            result += (current_pixel - average_brightness) * (neighbor_pixel - average_brightness)
    return result/count


def calc_vertical_covariation(image):
    result = .0
    average_brightness = get_img_avg_brightness(image)
    count = image.height * (image.width - 1)
    for y in range(image.height - 1):
        for x in range(image.width):
            current_pixel = image.getpixel((x, y))
            neighbor_pixel = image.getpixel((x, y + 1))
            result += (current_pixel - average_brightness) * (neighbor_pixel - average_brightness)
    return result/count


def calc_diagonal_covariation(image):
    result = .0
    average_brightness = get_img_avg_brightness(image)
    count = image.height * (image.width - 1)
    for y in range(image.height - 1):
        for x in range(image.width - 1):
            if image.mode == "L":
                current_pixel = image.getpixel((x, y))
                neighbor_pixel = image.getpixel((x + 1, y + 1))
            else:
                current_pixel = sum(image.getpixel((x, y))[:2])/3
                neighbor_pixel = sum(image.getpixel((x + 1, y + 1))[:2])/3
            result += (current_pixel - average_brightness) * (neighbor_pixel - average_brightness)
    return result/count


def standard_deviation(image):
    average_brightness = get_img_avg_brightness(image)
    corr_sum = .0
    for y in range(image.height):
        for x in range(image.width):
            corr_sum += pow(image.getpixel((x, y)) - average_brightness, 2)
    return sqrt(corr_sum)


def calc_coefs_of_correlations(image):
    image = image.convert("L")
    average_brightness = get_img_avg_brightness(image)
    result = {
        "horizontal": calc_horizontal_covariation(image)/standard_deviation(image),
        "vertical": calc_vertical_covariation(image)/standard_deviation(image),
        "diagonal": calc_diagonal_covariation(image)/standard_deviation(image),
    }
    return result

def get_img_with_changed_random_pixel(image):
    temp_image = image.copy()
    x = randint(0, image.width - 1)
    y = randint(0, image.height - 1)
    if temp_image.mode == "P":
        temp_image.putpixel((x,y), image.getpixel((x,y)) ^ 8)
    else:
        temp_image.putpixel((x,y), (image.getpixel((x,y))[0] ^ 8,) + image.getpixel((x,y))[1:])
    byte_img = base64.b64encode(temp_image.tobytes())
    byte_img = bytesToBin(byte_img)  # Сообщение в битах
    return byte_img

def get_npcr(image1, image2):
    result = .0
    changed_pixels_count = 0
    for x in range(image1.width):
        for y in range(image1.height):
            if image1.mode == "P":
                if image1.getpixel((x,y)) != image2.getpixel((x,y)):
                    changed_pixels_count += 1
            else:
                if sum(image1.getpixel((x,y))[:2])/3 != sum(image2.getpixel((x,y))[:2])/3:
                    changed_pixels_count += 1
    result = changed_pixels_count / (image1.height * image1.width)
    return result * 100

def get_uaci(image1, image2):
    result = .0
    image1 = image1.convert("P")
    image2 = image2.convert("P")
    bright_sum = .0
    for x in range(image1.width):
        for y in range(image1.height):
            bright_sum += abs(image1.getpixel((x,y)) - image2.getpixel((x,y)))/256
    result = bright_sum / (image1.height * image1.width)
    return result * 100
