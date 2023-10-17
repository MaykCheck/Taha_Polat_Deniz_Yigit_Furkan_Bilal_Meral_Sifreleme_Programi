from tkinter import * #bu şekilde yazarak bütün fonksiyonları tek seferde import etmiş oluyoruz
from tkinter import messagebox
import base64         #bu büyük ihtimalle pycharmde vardır ama yoksa pip instal!

#şimdi cryptopgraphy sitesinden aldığımız şifreleme komutlarını da buraya alalım ve kendi yazacağımız komutlara uygulayalım

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()       #bu soldaki kodları anlamana gerek yok çünkü encryption öğrenmiyoruz siteden aldım ve gerektiği yere yapıştırdım

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

# şimdi yazdığmız notları kaydetme programını yazalım

def notları_kaydet_ve_şifrele():
    başlık = başlık_girişi.get()
    metin = metin_girişi.get("1.0",END)
    şifre = şifre_girişi.get()
    if len(başlık) == 0 or len(metin) == 0 or len(şifre) == 0:
        messegabox.showinfo(title="HATA!", message="Lütfen Bütün Bilgileri Giriniz!")
    else:
        şifrelenmiş_mesaj = encode(şifre, metin)

        try:
            with open("şifrelenmişmesajım.txt", "a") as data_file:    #buradaki "a" append anlamına gelir ve dosyaya ekleme yap demek olur 
                data_file.write(f'\n{başlık}\n{şifrelenmiş_mesaj}')   #(a:append, w:write, r:read)
        except FileNotFoundError:
            with open("şifrelenmişmesajım.txt", "w") as data_file:
                data_file.write(f'\n{başlık}\n{şifrelenmiş_mesaj}')
        finally:
            başlık_girişi.delete(0, END)
            şifre_girişi.delete(0, END)
            metin_girişi.delete("1.0",END)

#şifre çözme programını yazarken de direkt çözme komutunu buraya yapıştırıp programımızı yazalım

def şifre_çözme():
    şifrelenmiş_mesaj = metin_girişi.get("1.0",END)
    şifre = şifre_girişi.get()

    if len(şifrelenmiş_mesaj) == 0 or len(şifre) == 0:
        messagebox.showinfo(title="HATA!", message="Lütfen bütün bilgileri giriniz!")
    else:
        try:
            çözülmüş_mesaj = decode(şifre, şifrelenmiş_mesaj)
            metin_girişi.delete("1.0",END)
            metin_girişi.insert("1.0", çözülmüş_mesaj)
        except:
            messagebox.showinfo(title="HATA!", message="Şifrelenmiş verinin doğrulundan emin olunuz!")

#GUI: şimdi de pencereyi tasarlayalım

FONT=("Verdena",20,"normal")
window = Tk()
window.title("Şifreli Notlar")
window.config(padx=30, pady=30)

başlık_labelı = Label(text="Başlığınızı Giriniz", font=FONT)
başlık_labelı.pack()

başlık_girişi = Entry(width=30)
başlık_girişi.pack()

metin_girişi_başlığı = Label(text="Şifrelenecek Metninizi Giriniz." font=FONT)
metin_girişi_başlığı.pack()

metin_girişi = Text(width=50,height=25)   #buradaki genişlik ve yükseklik değerlerini pencereye bakarak kendin ayarla buradaki interpreter çalışmıyor
metin_girişi.pack()

şifre_başlığı = Label(text="Şifrenizi Giriniz", font=FONT)
şifre_başlığı.pack()

şifre_girişi = Entry(width=30)
şifre_girişi.pack()

kayıt_butonu = Button(text="Kaydet ve Şifrele", command=notları_kaydet_ve_şifrele)
kayıt_butonu.pack()

şifre_çözme_butonu = Button(text="Şifreyi Çöz", command=şifre_çözme)
şifre_çözme_butonu.pack()

window.mainloop()


#bunları yapışıtırıp çalıştır ve bug bulmayı dene eğer bozulursa ya da hiç çalışmazsa chatgpt'ye sor ve doğrusunu commit yoluyla githubda güncelle ikinizin de yetkisi var 
