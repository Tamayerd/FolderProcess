import os   #işletim sisteminde kullanılar bazı fonksiyonlara erişimi sağlar.
import hashlib
import requests

API_KEY = "773c207a51b512f67225834c529c96ab20010c350beb86fee7ecd43b83c77123"

# Dosya türünü belirleme
def get_file_type(filename):
    return os.path.splitext(filename)[1]

# Dosya taraması
def scan_file(filename):
   
    # Dosya boyutu sınırı
    MAX_FILE_SIZE = 1024 * 1024 * 100  # 100MB' dan büyük mü öğremek için
   
    # Dosya boyutunu kontrol etme
    if os.path.getsize(filename) > MAX_FILE_SIZE:
        print(f"Dosya boyutu çok büyük {MAX_FILE_SIZE} ")
        return False
    
    # Dosya içeriğini okuma
    with open(filename, "rb") as f:
        file_data = f.read()
    
    # Dosya özeti hesaplama
    file_hash = hashlib.md5(file_data).hexdigest() #hexdigest verimizin şifrelenmiş halini str olarak döndürür

    # Özeti virüs veritabanı ile karşılaştırma
    if check_virus_database(file_hash):
        print("Dosyada virüs bulunabilir.")
        return False
    else:
        print("Dosya Temiz.")
        return True

# Virüs veritabanı kontrolü
def check_virus_database(file_hash):

# VirusTotal API'nin HTTP URL'si
    url = f"https://www.virustotal.com/vtapi/v2/file/report?apikey={API_KEY}&resource={file_hash}"
    
    # API'ye istek gönderme
    response = requests.get(url)
    
    # Yanıtın JSON verilerini alma
    json_data = response.json()
    
    # Virüs taraması sonucunu kontrol etme
    if json_data["response_code"] == 1 and json_data["positives"] > 0:
        print(f"VirusTotal {json_data['positives']} pozitif tespit etti {json_data['total']} toplam taramadan")
        return True
    else:
        print("Dosya temiz")
        return False

# Kullanım örneği
filename = "malware-example.txt"
file_type = get_file_type(filename)
print(f"Dosya tipi: {file_type}")
scan_file(filename)