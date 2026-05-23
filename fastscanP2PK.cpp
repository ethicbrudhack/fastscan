// ==========================
// FASTSCAN v2 – CPU TWEAK-ADD
// BEZ JACOBIAN, SUPER STABILNE
// ==========================

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <cerrno>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/bn.h>
#include <secp256k1.h>

// ===============================
// PARAMETRY
// ===============================
static const uint64_t BLOCK_SIZE = 100'000ULL;
static const int THREAD_COUNT = 32;

std::mutex log_mutex;

// ===============================
// MAPOWANIE PLIKÓW 20B
// ===============================
class MMapFile {
public:
    MMapFile(const char* path) {
        fd = ::open(path, O_RDONLY);
        if (fd < 0) throw std::runtime_error(std::string("open: ") + strerror(errno));

        struct stat st{};
        if (fstat(fd, &st) != 0)
            throw std::runtime_error(std::string("fstat: ") + strerror(errno));

        size = st.st_size;
        if (size == 0 || size % 20 != 0)
            throw std::runtime_error("invalid bin file");

        data = (const unsigned char*) mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0);
        if (data == MAP_FAILED)
            throw std::runtime_error(std::string("mmap: ") + strerror(errno));
    }

    ~MMapFile() {
        if (data) munmap((void*)data, size);
        if (fd >= 0) close(fd);
    }

    const unsigned char* ptr() const { return data; }
    size_t length() const { return size; }

private:
    int fd;
    const unsigned char* data;
    size_t size;
};

bool contains_address_bin(const MMapFile& mm, const unsigned char addr20[20]) {
    const unsigned char* base = mm.ptr();
    size_t count = mm.length() / 20;

    size_t lo = 0, hi = count;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        const unsigned char* midp = base + mid * 20;

        int cmp = memcmp(midp, addr20, 20);
        if (cmp == 0) return true;
        if (cmp < 0) lo = mid + 1;
        else hi = mid;
    }
    return false;
}

// ===============================
// HASH TOOLS
// ===============================
inline void sha256_once(const unsigned char* d, size_t n, unsigned char out[32]) {
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, d, n);
    SHA256_Final(out, &c);
}

inline void ripemd160_once(const unsigned char* d, size_t n, unsigned char out[20]) {
    RIPEMD160_CTX r;
    RIPEMD160_Init(&r);
    RIPEMD160_Update(&r, d, n);
    RIPEMD160_Final(out, &r);
}

inline void pubkey_hash160(const unsigned char* pub, size_t len, unsigned char out[20]) {
    unsigned char sh[32];
    sha256_once(pub, len, sh);
    ripemd160_once(sh, 32, out);
}
std::vector<uint8_t> make_p2pk_script(const uint8_t pubkey65[65]) {
    std::vector<uint8_t> script;
    script.reserve(67);

// HASH160(pubkey), NIE scriptu
//unsigned char h160[20];
//pubkey_hash160(pub65, 65, h160);


    return script;
}
void hash160_vector(const std::vector<unsigned char>& in, unsigned char out[20]) {
    unsigned char sha[32];

    SHA256_CTX s;
    SHA256_Init(&s);
    SHA256_Update(&s, in.data(), in.size());
    SHA256_Final(sha, &s);

    RIPEMD160_CTX r;
    RIPEMD160_Init(&r);
    RIPEMD160_Update(&r, sha, 32);
    RIPEMD160_Final(out, &r);
}
static const char* BASE58 =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
std::string base58check(const std::vector<unsigned char>& data) {
    BIGNUM* bn = BN_new();
    BN_bin2bn(data.data(), data.size(), bn);

    BIGNUM *dv = BN_new(), *rem = BN_new(), *b58 = BN_new();
    BN_CTX* ctx = BN_CTX_new();

    BN_set_word(b58, 58);

    std::string out;

    while (!BN_is_zero(bn)) {
        BN_div(dv, rem, bn, b58, ctx);
        unsigned long idx = BN_get_word(rem);
        out.insert(out.begin(), BASE58[idx]);
        BN_copy(bn, dv);
    }

    for (unsigned char c : data)
        if (c == 0x00) out.insert(out.begin(), '1');
        else break;

    BN_free(bn);
    BN_free(dv);
    BN_free(rem);
    BN_free(b58);
    BN_CTX_free(ctx);

    return out;
}
bool base58_to_hash160(const std::string& input, unsigned char out[20]) {
    static const char* ALPHABET =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    std::vector<unsigned char> temp(25, 0);

    for (char c : input) {
        const char* p = strchr(ALPHABET, c);
        if (!p) return false;
        int val = p - ALPHABET;

        int carry = val;
        for (int i = 24; i >= 0; --i) {
            carry += temp[i] * 58;
            temp[i] = carry & 0xFF;
            carry >>= 8;
        }
        if (carry != 0) return false;
    }

    memcpy(out, temp.data() + 1, 20);
    return true;
}

// ===============================
// FAST PUBKEY CONTEXT
// ===============================
struct FastPubCtx {
    secp256k1_context* ctx;
    secp256k1_pubkey pub;
    bool initialized = false;
};

// dodanie +1 do pubkey
inline void fast_priv_add_one(FastPubCtx& pc) {
    static const unsigned char ONE32[32] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1
    };
    secp256k1_ec_pubkey_tweak_add(pc.ctx, &pc.pub, ONE32);
}

inline void fast_load_priv(FastPubCtx& pc, const unsigned char priv[32]) {
    secp256k1_ec_pubkey_create(pc.ctx, &pc.pub, priv);
    pc.initialized = true;
}


bool generate_full_fake_p2pk_hash160(const secp256k1_context* ctx,
                                     const secp256k1_pubkey& pub,
                                     unsigned char out20[20])
{
    //
    // 1) Uncompressed pubkey (65 bytes)
    //
    unsigned char pub65[65];
    size_t len = 65;
    secp256k1_ec_pubkey_serialize(ctx, pub65, &len, &pub, SECP256K1_EC_UNCOMPRESSED);

    //
    // 2) (Opcjonalnie) Zbuduj surowy P2PK script: 41 PUB65 AC
    //
    std::vector<unsigned char> script;
    script.reserve(67);
    script.push_back(0x41);
    script.insert(script.end(), pub65, pub65 + 65);
    script.push_back(0xAC);

    //
    // 3) HASH160(pubkey) — tak działa FAKE P2PK w blockchain.info
    //
    unsigned char h160_pub[20];
    {
        unsigned char sha[32];
        SHA256(pub65, 65, sha);

        RIPEMD160(sha, 32, h160_pub);
    }

    //
    // 4) Base58Check: prefix 0x00 + HASH160(pub)
    //
    std::vector<unsigned char> ext;
    ext.push_back(0x00);
    ext.insert(ext.end(), h160_pub, h160_pub + 20);

    unsigned char h1[32], h2[32];
    SHA256(ext.data(), ext.size(), h1);
    SHA256(h1, 32, h2);
    ext.insert(ext.end(), h2, h2 + 4);

    std::string addr = base58check(ext);

    //
    // 5) Decode Base58 → HASH160 (20 bytes)
    //
    return base58_to_hash160(addr, out20);
}

// ===============================
// SAVE FOUND
// ===============================
void save_found(const char* prefix, const unsigned char priv[32], bool comp, const std::string& address)
{
    std::lock_guard<std::mutex> lk(log_mutex);

    std::ofstream f("found.txt", std::ios::app);
    f << prefix << (comp ? " (C) " : " (U) ");

    for (int i = 0; i < 32; i++)
        f << std::hex << std::setw(2) << std::setfill('0') << (int)priv[i];

    f << "  ADDR=" << address << "\n";

    std::cout << "\n🎯 ZNALEZIONO " << prefix
              << (comp ? " (C)\n" : " (U)\n")
              << "➡️ ADRES = " << address << "\n";
}


// ===============================
// PROGRESS
// ===============================
void save_state(uint64_t r, uint64_t c) {
    std::ofstream f("progress.txt", std::ios::trunc);
    f << r << "\n" << c << "\n";
}

bool load_state(uint64_t& r, uint64_t& c) {
    std::ifstream f("progress.txt");
    if (!f.is_open()) return false;
    f >> r >> c;
    return true;
}

// ===============================
// MAIN
// ===============================
int main(int argc, char* argv[]) {

    if (argc < 4) {
        std::cout << "Użycie: ./scan adresy.bin start_bit end_bit [--resume]\n";
        return 1;
    }

    MMapFile mm(argv[1]);
    int start_bit = std::stoi(argv[2]);
    int end_bit   = std::stoi(argv[3]);
    bool resume = (argc >= 5 && std::string(argv[4]) == "--resume");

    secp256k1_context* ctx_master =
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    BN_CTX* bnctx = BN_CTX_new();
    BIGNUM *R0 = BN_new(), *R1 = BN_new(), *two = BN_new();
    BN_set_word(two, 2);

    BIGNUM *bs = BN_new(), *be = BN_new();
    BN_set_word(bs, start_bit);
    BN_set_word(be, end_bit);

    BN_exp(R0, two, bs, bnctx);
    BN_exp(R1, two, be, bnctx);

    BIGNUM* RLEN = BN_new();
    BN_sub(RLEN, R1, R0);

    uint64_t round_idx = 1;
    uint64_t chunk_idx = 0;

    if (resume) load_state(round_idx, chunk_idx);

    while (true) {

        uint64_t CHUNKS = round_idx * 21989898ULL;

        std::cout << "\n🔁 Runda " << round_idx
                  << " | chunks=" << CHUNKS
                  << " | BLOCK=" << BLOCK_SIZE << "\n";

        BIGNUM* bn_chunks = BN_new();
        BN_set_word(bn_chunks, CHUNKS);

        BIGNUM* stride = BN_new();
        BN_div(stride, nullptr, RLEN, bn_chunks, bnctx);
          
          
        // =====================================================
// DEBUG: wypisz pierwsze 15 chunków (pełne 32 bajty)
// =====================================================
{
    BN_CTX* tc = BN_CTX_new();
    BIGNUM* tmp = BN_new();
    BIGNUM* index_bn = BN_new();

    std::cout << "\n📌 Pierwsze 15 chunków (pełne 32 bajty):\n";

    for (int ci = 0; ci < 15 && ci < CHUNKS; ci++) {

        BN_set_word(index_bn, ci);

        // tmp = R0 + ci * stride
        BN_mul(tmp, index_bn, stride, tc);
        BN_add(tmp, tmp, R0);

        unsigned char priv_debug[32];
        BN_bn2binpad(tmp, priv_debug, 32);

        char fullhex[65];
        for (int z = 0; z < 32; z++)
            sprintf(fullhex + z*2, "%02X", priv_debug[z]);

        std::cout << "Chunk " << ci
                  << "  PRIV=" << fullhex << "\n";
    }

    BN_free(tmp);
    BN_free(index_bn);
    BN_CTX_free(tc);
}

        std::atomic<uint64_t> next(chunk_idx);
        std::atomic<uint64_t> keys_done(0), chunks_done(0);
        std::atomic<bool> stop(false);

        // Speed monitor
        std::thread monitor([&]() {
            uint64_t last = 0;
            while (!stop.load()) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                uint64_t now = keys_done.load();
                double m = (now - last) / 2'000'000.0;
                last = now;

                std::cout << "\r⚙️ "
                          << std::fixed << std::setprecision(2)
                          << m << " Mkeys/s"
                          << " | chunk " << chunks_done
                          << "/" << CHUNKS
                          << std::flush;
            }
        });

        std::vector<std::thread> pool;

        for (int t = 0; t < THREAD_COUNT; t++) {
            pool.emplace_back([&, t]() {

                BN_CTX* lc = BN_CTX_new();
                BIGNUM *bn_i = BN_new(), *bn_off = BN_new(), *privBN = BN_new();

                FastPubCtx fctx;
                fctx.ctx = secp256k1_context_clone(ctx_master);

                while (true) {

                    uint64_t i = next.fetch_add(1);
                    if (i >= CHUNKS) break;

                    BN_set_word(bn_i, i);
                    BN_mul(bn_off, bn_i, stride, lc);
                    BN_add(privBN, R0, bn_off);

                    unsigned char priv[32];

                    fctx.initialized = false;

                    for (uint64_t k = 0; k < BLOCK_SIZE; k++) {

                        BN_bn2binpad(privBN, priv, 32);

                        if (!fctx.initialized) fast_load_priv(fctx, priv);
                        else fast_priv_add_one(fctx);

unsigned char hp2pk[20];

if (generate_full_fake_p2pk_hash160(fctx.ctx, fctx.pub, hp2pk))

 {
    if (contains_address_bin(mm, hp2pk)) {
    // Wygeneruj FAKE adres (znowu)
    unsigned char pub65[65];
    size_t len = 65;
    secp256k1_ec_pubkey_serialize(fctx.ctx, pub65, &len, &fctx.pub, SECP256K1_EC_UNCOMPRESSED);

    // HASH160(pubkey)
    unsigned char sha[32];
    SHA256(pub65, 65, sha);

    unsigned char h160_pub[20];
    RIPEMD160(sha, 32, h160_pub);

    // prefix + checksum
    std::vector<unsigned char> ext;
    ext.push_back(0x00);
    ext.insert(ext.end(), h160_pub, h160_pub + 20);

    unsigned char h1[32], h2[32];
    SHA256(ext.data(), ext.size(), h1);
    SHA256(h1, 32, h2);
    ext.insert(ext.end(), h2, h2 + 4);

    std::string addr = base58check(ext);

    // WYPISANIE NA EKRAN
    {
        std::lock_guard<std::mutex> lk(log_mutex);
        std::cout << "\n🔑 FAKE P2PK ADDRESS = " << addr << "\n";
    }

    save_found("P2PK", priv, true, addr);

}

}


                        BN_add_word(privBN, 1);
                        keys_done++;
                    }

                    save_state(round_idx, i);
                    chunks_done++;
                }

                BN_free(bn_i);
                BN_free(bn_off);
                BN_free(privBN);
                BN_CTX_free(lc);
                secp256k1_context_destroy(fctx.ctx);
            });
        }

        for (auto& th : pool) th.join();
        stop = true;
        monitor.join();

        std::cout << "\n➡️ Runda " << round_idx << " zakończona.\n";

        round_idx++;
        chunk_idx = 0;

        BN_free(bn_chunks);
        BN_free(stride);
    }

    return 0;
}
