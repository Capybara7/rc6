from datetime import datetime
from django.shortcuts import render
from django.http import HttpRequest
from force import *
from RC6 import *
from bitstring import BitArray

def encrypt_photo(request):
    if request.method == 'POST':
        photo = image_to_bits(request.FILES.get('photo'))
        img = bits_to_img_not_save(photo)
        bits_to_image(photo, 'app\\static\\img.png')
        encryption_key = request.POST.get('encryption-key')
        encryption_mode = request.POST.get('encryption-mode')
        kolvo_raundov = int(request.POST.get('kol-vo-raundov'))
        cipher_mode = request.POST.get('cipher-mode')

        if encryption_mode == 'ecb' and cipher_mode == 'enc':
            shifr_img = [photo[0], photo[1], encode_ECB(photo[2], encryption_key, kolvo_raundov)]
        if encryption_mode == 'cbc' and cipher_mode == 'enc':
            iv = "Initialization V"
            shifr_img = [photo[0], photo[1], encode_CBC(photo[2], encryption_key, kolvo_raundov, iv)]
        if encryption_mode == 'ecb' and cipher_mode == 'dec':
            deshifr_img = [photo[0], photo[1], decode_ECB(photo[2], encryption_key, kolvo_raundov)]
        if encryption_mode == 'cbc' and cipher_mode == 'dec':
            iv = "Initialization V"
            deshifr_img = [photo[0], photo[1], decode_CBC(photo[2], encryption_key, kolvo_raundov, iv)]

        if cipher_mode == 'enc':
            cipher_mode = True
            output = 'app\\static\\enc.png'
            sh_img = bits_to_image(shifr_img, output)
        if cipher_mode == 'dec':
            cipher_mode = False
            output = 'app\\static\\dec.png'
            bits_to_image(deshifr_img, output)

        #Криптостойкость
        if cipher_mode == True:
            res = []
            res.append({})
        
            coefs = calc_coefs_of_correlations(img)
            res[0]['src_entropy'] = round(img.entropy(),4)
            res[0]['src_covar_h'] = round(coefs['horizontal'], 4)
            res[0]['src_covar_v'] = round(coefs['vertical'], 4)
            res[0]['src_covar_d'] = round(coefs['diagonal'], 4)

            coefs = calc_coefs_of_correlations(sh_img)
            res[0]['enc_entropy'] = round(sh_img.entropy(),4)
            res[0]['enc_covar_h'] = round(coefs['horizontal'], 4)
            res[0]['enc_covar_v'] = round(coefs['vertical'], 4)
            res[0]['enc_covar_d'] = round(coefs['diagonal'], 4)

            changed_pixel_image = get_img_with_changed_random_pixel(img)
            if encryption_mode == 'cbc':
                changed_pixel_enc_bytes = encode_CBC(changed_pixel_image, encryption_key, kolvo_raundov, iv)
            else:
                changed_pixel_enc_bytes = encode_ECB(changed_pixel_image, encryption_key, kolvo_raundov)
            bits = BitArray(bin=changed_pixel_enc_bytes)
            bytes_data = bits.tobytes()
            changed_pixel_enc = Image.frombytes(photo[0], photo[1], bytes_data)

            npcr = get_npcr(changed_pixel_enc, sh_img)
            uaci = get_uaci(changed_pixel_enc, sh_img)

            context = {
                'cipher_mode': cipher_mode,  # Зашифрованные данные
                'res_src_entropy': res[0]['src_entropy'],
                'res_src_covar_h': res[0]['src_covar_h'],
                'res_src_covar_v': res[0]['src_covar_v'],
                'res_src_covar_d': res[0]['src_covar_d'],

                'res_enc_entropy': res[0]['enc_entropy'],
                'res_enc_covar_h': res[0]['enc_covar_h'],
                'res_enc_covar_v': res[0]['enc_covar_v'],
                'res_enc_covar_d': res[0]['enc_covar_d'],

                'npcr_label': npcr,
                'uaci_label': uaci

            }
            return render(request, 'app/result.html', context)
        else:
            context = {
                'cipher_mode': cipher_mode  # Зашифрованные данные
            }
            return render(request, 'app/result.html', context)

    return render(request, 'app/encryption.html')

def home(request):
    """Renders the home page."""
    assert isinstance(request, HttpRequest)
    return render(
        request,
        'app/encryption.html'
    )