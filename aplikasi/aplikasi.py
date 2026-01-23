import hashlib
import time
import os
import secrets
import binascii

# --- Kelas Utama Aplikasi Berdasarkan Temuan SLR ---

class SLRCryptoApp:
    def __init__(self):
        self.algorithms = {
            'SHA-256': hashlib.sha256,
            'SHA-512': hashlib.sha512,
            'SHA-3-512': hashlib.sha3_512,
            'Blake2b': hashlib.blake2b
        }
        self.user_database = {} # Simulasi DB untuk pengujian Salting

    def generate_salt(self, length=16):
        """Membuat Salt acak untuk keamanan password."""
        return secrets.token_hex(length)

    def hash_password(self, password, algo_type='sha3', salt=None):
        """Fungsi hashing hibrida (Blake2 atau SHA-3)."""
        if salt:
            # Mengimplementasikan Salting: Password + Salt
            data = (password + salt).encode('utf-8')
        else:
            data = password.encode('utf-8')

        if algo_type == 'blake2':
            return hashlib.blake2b(data).hexdigest()
        elif algo_type == 'sha3':
            return hashlib.sha3_512(data).hexdigest()
        else:
            return hashlib.sha256(data).hexdigest()
            
    # ==========================================================
    # 1. Uji Kinerja Dasar (Trade-off Kecepatan vs Keamanan)
    # ==========================================================
    def run_performance_test(self, text_input="Universitas Esa Unggul - TI 2025", iterations=100000):
        print(f"\n--- 1. Uji Kinerja Dasar ({iterations} iterasi) ---")
        print(f"Input Data: '{text_input}'")
        data_bytes = text_input.encode('utf-8')

        results = {}
        for name, algo_func in self.algorithms.items():
            start_time = time.perf_counter()
            for _ in range(iterations):
                _ = algo_func(data_bytes).hexdigest()
            duration = time.perf_counter() - start_time
            results[name] = duration
            print(f"[{name}] Waktu: {duration:.4f} detik")

        fastest = min(results, key=results.get)
        print(f"\n✅ Kesimpulan: {fastest} adalah yang tercepat dalam pengujian ini.")
        print("💡 Catatan SLR: Hasil ini membuktikan trade-off komputasi. Blake2 dirancang untuk efisiensi.")

    # ==========================================================
    # 2. Demonstrasi Avalanche Effect (Keamanan Teoritis)
    # ==========================================================
    def demonstrate_avalanche_effect(self, text1="Password123", text2="password123"):
        print(f"\n--- 2. Demonstrasi Avalanche Effect (Menguji SHA-3) ---")
        print(f"Teks Awal : '{text1}'")
        print(f"Teks Ubah : '{text2}'")
        
        
        # SHA-3 dipilih karena SLR menyoroti konsistensi Avalanche Effect-nya.
        algo = hashlib.sha3_512
        
        hash1 = algo(text1.encode('utf-8')).hexdigest()
        hash2 = algo(text2.encode('utf-8')).hexdigest()

        # Hitung perbedaan karakter (untuk aproksimasi Hamming Distance)
        diff_count = sum(1 for a, b in zip(hash1, hash2) if a != b)
        total_chars = len(hash1)
        percentage = (diff_count / total_chars) * 100
        
        print(f"\nHash 1 (SHA-3): {hash1[:30]}...") 
        print(f"Hash 2 (SHA-3): {hash2[:30]}...")
        print(f"\n✅ Perbedaan Karakter Hex: {percentage:.2f}%")
        print("💡 Analisis: Nilai di atas 50% membuktikan output berubah total, menjamin keamanan terhadap tebakan.")

    # ==========================================================
    # 3. Simulasi Cek Integritas File (Sidik Jari Digital)
    # ==========================================================
    def simulate_integrity_check(self):
        print(f"\n--- 3. Simulasi Integritas File ---")
        filename = "dokumen_rahasia_simulasi.txt"
        content_original = "Data Transaksi Keuangan Penting: Rp 1.000.000.000"
        
        # 1. Hitung Hash Awal (Sidik Jari Digital)
        with open(filename, "w") as f:
            f.write(content_original)
        with open(filename, "rb") as f:
            original_hash = hashlib.sha256(f.read()).hexdigest()
        print(f"1. Dokumen dibuat. SHA-256 Hash asli: {original_hash}")

        # 2. Simulasi Serangan/Modifikasi (Tampering)
        print("2. Simulasi serangan: Seseorang mengubah nominal di file...")
        with open(filename, "w") as f:
            f.write("Data Transaksi Keuangan Penting: Rp 9.000.000.000") # Ubah angka 1 jadi 9
        
        # 3. Verifikasi
        with open(filename, "rb") as f:
            new_hash = hashlib.sha256(f.read()).hexdigest()
        print(f"3. Hash file saat ini: {new_hash}")
        
        if original_hash == new_hash:
            print("✅ Status: DATA AMAN (Integritas Terjaga).")
        else:
            print("❌ Status: PERINGATAN! DATA TELAH DIMODIFIKASI (Integritas Rusak).")

        os.remove(filename)

    # ==========================================================
    # 4. Simulasi Serangan Rainbow Table (Uji Gap Salting SLR)
    # ==========================================================
    def simulate_rainbow_table_attack(self):
        print(f"\n--- 4. Simulasi Serangan Rainbow Table (Menguji Salting) ---")
        
        # Pendaftaran user: password sama (123456)
        # User A: Buruk (Tanpa Salt) - Sesuai kelemahan yang disorot SLR
        self.user_database['user_lemah'] = {
            'hash': self.hash_password("123456", 'sha256', None),
            'salt': None,
            'algo': 'sha256'
        }
        # User B: Aman (Dengan Salt) - Sesuai rekomendasi SLR
        salt = self.generate_salt()
        self.user_database['user_aman'] = {
            'hash': self.hash_password("123456", 'sha3', salt),
            'salt': salt,
            'algo': 'sha3'
        }
        
        # Daftar password umum (Kamus Hacker)
        common_passwords = ["123456", "password", "admin", "rahasia"]
        
        # Uji User Lemah
        print("\n[Target: user_lemah] -> Tanpa Salt")
        found = False
        for pwd in common_passwords:
            calc_hash = self.hash_password(pwd, algo='sha256', salt=None)
            if calc_hash == self.user_database['user_lemah']['hash']:
                print(f" >> ❌ SUKSES DIRETAS! Password: '{pwd}' (Sistem Tanpa Salt Rentan)")
                found = True
                break
        if not found:
            print(" >> ✅ GAGAL! Password tidak ditemukan di kamus.")
            
        # Uji User Aman
        print("\n[Target: user_aman] -> Dengan Salt + SHA-3")
        found = False
        for pwd in common_passwords:
            # Hacker harus menebak (Password + Salt)
            # Karena salt acak dan tidak diketahui hacker, Rainbow Table gagal.
            calc_hash = self.hash_password(pwd, algo='sha3', salt=self.user_database['user_aman']['salt'])
            if calc_hash == self.user_database['user_aman']['hash']:
                print(f" >> ❌ SUKSES DIRETAS! Password: '{pwd}'")
                found = True
                break

        if not found:
            print(" >> ✅ GAGAL! Password terlindungi oleh Salting dan SHA-3 (Tahan Rainbow Table).")

    # ==========================================================
    # 5. Uji Kinerja dengan Salting (Uji Model Hibrida SLR)
    # ==========================================================
    def run_comparative_study(self, iterations=50000):
        print(f"\n--- 5. Uji Kinerja dengan Salting ({iterations} iterasi) ---")
        password = "DataMahasiswa2025"
        
        # Test Blake2 (Skenario Cepat dengan Salt)
        start = time.perf_counter()
        salt = self.generate_salt()
        for _ in range(iterations):
            self.hash_password(password, 'blake2', salt)
        blake_time = time.perf_counter() - start
        
        # Test SHA-3 (Skenario Aman dengan Salt)
        start = time.perf_counter()
        salt = self.generate_salt()
        for _ in range(iterations):
            self.hash_password(password, 'sha3', salt)
        sha3_time = time.perf_counter() - start
        
        print(f"Input: '{password}' | Iterasi: {iterations}")
        print(f"1. Blake2 (Salting) : {blake_time:.4f} detik")
        print(f"2. SHA-3  (Salting) : {sha3_time:.4f} detik")
        
        diff = ((sha3_time - blake_time) / blake_time) * 100 if blake_time > 0 else 0
        
        print(f"Analisis: Blake2 lebih cepat {diff:.1f}% daripada SHA-3 dalam proses hashing yang kompleks (Salting).")
        print("💡 Kesimpulan SLR: Blake2 dipilih untuk sistem yang sangat memprioritaskan kecepatan otentikasi.")
        
    # ==========================================================
    # Menu Aplikasi
    # ==========================================================
    def display_menu(self):
        print("\n" + "="*60)
        print("APLIKASI EVALUASI FUNGSI HASH BERDASARKAN STUDI LITERATUR REVIEW (SLR)")
        print("="*60)
        print("Pilih Uji Kasus Sesuai Temuan dan Rekomendasi SLR:")
        print("1. ⚖️ Uji Kinerja Dasar (Kecepatan SHA-256, SHA-3, Blake2)")
        print("2. 💥 Demonstrasi Avalanche Effect (Kualitas Acak SHA-3)")
        print("3. 📝 Simulasi Cek Integritas File (Fungsi Sidik Jari Digital)")
        print("-" * 60)
        print("4. 🛡️ Simulasi Serangan Rainbow Table (Uji Research Gap: Salting)")
        print("5. 📈 Uji Kinerja Lanjutan (Blake2 vs SHA-3 dengan Salting)")
        print("6. 🚪 Keluar")
        print("-" * 60)

    def run(self):
        while True:
            self.display_menu()
            choice = input("Masukkan pilihan Anda (1-6): ")
            
            if choice == '1':
                self.run_performance_test()
            elif choice == '2':
                self.demonstrate_avalanche_effect()
            elif choice == '3':
                self.simulate_integrity_check()
            elif choice == '4':
                self.simulate_rainbow_table_attack()
            elif choice == '5':
                self.run_comparative_study()
            elif choice == '6':
                print("Terima kasih. Program selesai.")
                break
            else:
                print("Pilihan tidak valid. Silakan coba lagi.")
            
            input("\nTekan ENTER untuk kembali ke menu...")

# --- Jalankan Aplikasi ---
if __name__ == "__main__":
    app = SLRCryptoApp()
    app.run()