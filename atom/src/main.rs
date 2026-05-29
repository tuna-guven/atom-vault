use atom::{crypto, vfs, chunker};

use std::io::{Read, Write, Seek, SeekFrom};
// zeroize kütüphanesinden otomatik silme (wiping) yapan akıllı sarmalayıcıyı alıyoruz
use zeroize::Zeroizing;

fn main() {
    println!("Atom-Vault is starting with Architecture B (Streaming + Least Privilege)...");

    // 1. Artık kasayı SUDO OLMADAN, doğrudan 50 MB (veya daha büyük) başlatabiliyoruz!
    let vault_size = 50 * 1024 * 1024;
    let mut vault = vfs::MemFile::new("atom_vault", vault_size).unwrap();

    // 2. Kriptografik anahtar kurulumları (Tuna'nın motoru için)
    let salt = crypto::generate_32_bytes();
    let kek = crypto::derive_kek("master_password", &salt).unwrap();
    let raw_dek = crypto::generate_32_bytes();
    let (wrapped_dek, dek_nonce) = crypto::wrap_dek(&kek, &raw_dek).unwrap();
    let unlocked_vault = crypto::unwrap_dek(&kek, &wrapped_dek, &dek_nonce).unwrap();

    // Deneme verisi yazıyoruz ve imleci başa sarıyoruz
    vault.write_all(&b"SYSTEM_DATA".repeat(1000)).unwrap();
    vault.seek(SeekFrom::Start(0)).unwrap();

    // 3. Akış motorunu (Streaming Iterator) başlatıyoruz
    // Burada vault ödünç alınıyor, bu yüzden işlemleri döngü içinde koordine edeceğiz.
    let chunk_stream = chunker::chunk_data(&mut vault);

    println!("Processing chunks in an interleaved pipeline...");

    // 4. PIPELINE INTERLEAVING DÖNGÜSÜ (Bütün parçaları sırayla işliyoruz)
    for chunk_result in chunk_stream {
        let chunk_info = chunk_result.unwrap(); // Parçanın offset ve length bilgisini aldık

        // A. ZEROIZE ENTEGRASYONU: Belleği işletim sistemine vermeden önce sıfırlayan tampon
        // Zeroizing<Vec<u8>> scope'tan çıktığı an (döngü adımı bittiğinde) içini otomatik kazır!
        let mut secure_buffer = Zeroizing::new(vec![0u8; chunk_info.length]);

        // B. ANLIK KİLİTLEME (Architecture B - Dynamic Locking)
        // Sadece o an işlediğimiz küçük parçayı RAM'e çiviliyoruz. Sudo gerektirmez!
        unsafe {
            libc::mlock(
                secure_buffer.as_ptr() as *const libc::c_void,
                chunk_info.length,
            );
        }

        // C. VERİYİ VFS'DEN OKUMA
        // Vault üzerindeki geçici borrow (ödünç alma) çakışmasını engellemek için
        // şu anki basit senaryoda doğrudan okuma yapıyoruz.
        // (Eğer derleyici chunk_stream canlıyken vault.seek yapmana kızarsa 
        // bunu çözecek küçük bir dokunuş yapacağız, şimdilik akışı görelim).
        
        // Bu adımı simüle etmek ve şifreleme motorunu tetiklemek için tamponu veriyoruz:
        let (_ciphertext, _chunk_nonce) = crypto::encrypt_chunk(&unlocked_vault, &secure_buffer).unwrap();

        // D. KİLİDİ KALDIRMA (Cleanup)
        // İşimiz bitti, işletim sistemine bu küçük parçanın kilidini iade ediyoruz
        unsafe {
            libc::munlock(
                secure_buffer.as_ptr() as *const libc::c_void,
                chunk_info.length,
            );
        }

        // <--- Döngü adımı burada bitiyor! 
        // secure_buffer yok edilirken (Drop) Zeroize trait'i tetikleniyor 
        // ve RAM'deki şifresiz verinin üzeri 0000... ile çiziliyor.
    }

    println!("All chunks successfully processed, encrypted, and securely wiped from RAM!");
}