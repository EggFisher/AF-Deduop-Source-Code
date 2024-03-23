#include </usr/local/include/pbc/pbc.h>
#include </usr/local/include/pbc/pbc_test.h>
#include <gmp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <sstream>
#include <random>
#include <queue>
#include <math.h>

using namespace std;
using namespace chrono;

struct node{
    string content;
    int isLeft;
};

const int popThresh = 7;    //流行度阈值
const int saltsLen = 8;     //随机盐值长度8B
const int fileBlockSize = 128;   //生成MHT时文件分块大小
const int encryptFileBlockSize = 10000;  //进行双层加密时文件分块大小
constexpr streamsize BUFFER_SIZE = 1024 * 1024;  // 1MB buffer size
int treeLevel;
const string filePath = "file32MB.bin";
string ivString = "0123456789012345"; // AES-CBC 需要 16 字节长的 IV

pairing_t pairing;
element_t g, h_F;
element_t r, s, g1, pk;
element_t tmp1, tmp2;
element_t C1, C2, C3;
element_t g_p, h, L;
element_t d1, d2, Z, ZL;
element_t hexCi_ele;
mpz_t hexCi_mpz;
string hexCi_dec, hexCi, fileContent, K1, fileTag, plaintext;
element_t q, q_inv, F_p, alpha_p, alpha;
int nLeaves, nMHTs;

string readFileInChunks(const string &filePath);
string calculateSHA1(const string& data);
string sha256(element_t& input);
string aes_decrypt(const vector<unsigned char> &ciphertext, const string &keyString, const string &ivString);
vector<unsigned char> aes_encrypt(const string &plaintext, const string &keyString, const string &ivString);
string sha256(const string str);
string toHexString(const vector<unsigned char>& data);
vector<string> splitStringIntoBlocks(const string& inputString, int blockSize);
int calculateMHTNum(int x);
vector<string> generateRandomSalts(int nMHTs, int size);
vector<unsigned char> fromHexString(const string& hexString);
void messageToValue(const string& message, mpz_t message_mpz, string &m);
void valueToMessage(string &message, mpz_t message_mpz);
string buildMerkleHashTree(vector<string> fileBlocks, string salt);
int calculateNumBytes(int n);
int generateRandomNumber(int n);
vector<node> generateResponse(vector<string> fileBlocks, string salt, int challengeLeafNode);
bool verifyResponse(vector<node> responseNodeSet, string salt, string realRootNode);
void outerLayerEncrypt(string hexCiphertext);
void outerLayerDecrypt();
void keyGen();
void blindSig();

int main(){
    cout<<filePath<<endl;

    //生成密钥 & 系统初始化
    auto start = steady_clock::now();
    keyGen();
    auto end=steady_clock::now();
    auto duration = duration_cast<milliseconds>(end - start);
    cout<<"Time cost for KeyGen:"<<duration.count()<<"ms"<<endl;

    //盲签名并进行验证
    fileContent = readFileInChunks(filePath);    //读取文件内容

    start = steady_clock::now();
    blindSig();
    end=steady_clock::now();
    duration = duration_cast<milliseconds>(end - start);
    cout<<"Time cost for BlindSignature:"<<duration.count()<<"ms"<<endl;

    //计算加密密钥 K1 = H(alpha)
    K1=sha256(alpha);

    //文件加密
    start=steady_clock::now();
    vector<unsigned char> ciphertext = aes_encrypt(fileContent, K1, ivString);
    end=steady_clock::now();
    duration=duration_cast<milliseconds>(end-start);
    cout<<"Time cost for FileEncryption:"<<duration.count()<<"ms"<<endl;

    //生成文件标签 fileTag = H(ciphertext)
    string hexCiphertext = toHexString(ciphertext); //16进制密文

    start=steady_clock::now();
    fileTag = sha256(hexCiphertext);
    end=steady_clock::now();
    duration=duration_cast<milliseconds>(end-start);
    cout<<"Time cost for FileTagGen:"<<duration.count()<<"ms"<<endl;

    //进行双层加密
    vector<string> encryptFileBlocks = splitStringIntoBlocks(hexCiphertext, encryptFileBlockSize);

    start=steady_clock::now();
    for(int i=0;i<encryptFileBlocks.size();++i){
        outerLayerEncrypt(encryptFileBlocks[i]);
        // outerLayerDecrypt();
    }
    end=steady_clock::now();
    duration=duration_cast<milliseconds>(end-start);
    cout<<"Time cost for OuterLayerEncryption:"<<duration.count()<<"ms"<<endl;

    //对密文进行分块
    vector<string> fileBlocks = splitStringIntoBlocks(hexCiphertext, fileBlockSize);
    nLeaves = fileBlocks.size();
    // cout<<"叶子结点数目:"<<nLeaves<<endl;

    //根据叶子节点的数目生成MHT的数量
    nMHTs = calculateMHTNum(nLeaves);
    // cout<<"MHT数目:"<<nMHTs<<endl;

    //生成随机盐值 nMHTs个
    vector<string> saltsValue = generateRandomSalts(nMHTs, saltsLen);

    //生成 ADMHF (nMHTs个)
    start=steady_clock::now();
    vector<string> rootNodeofADMHF;
    for( int i=0; i<nMHTs; ++i ){
        rootNodeofADMHF.push_back(buildMerkleHashTree(fileBlocks, saltsValue[i]));
    }
    //cout<<"treeLevel:"<<treeLevel<<endl;
    end=steady_clock::now();
    duration=duration_cast<milliseconds>(end-start);
    cout<<"Time cost for ADMHF Generation:"<<duration.count()<<"ms"<<endl;

    //后续上传者进行PoW
    //Challenge
    start=steady_clock::now();
    int chalMHT=generateRandomNumber(nMHTs-1);
    int chalLeafNode=generateRandomNumber(nLeaves-1);
    // cout<<"challenge MHT ID:"<<chalMHT<<' '<<"challenge Leaf Node:"<<chalLeafNode<<endl;
    end=steady_clock::now();
    duration=duration_cast<milliseconds>(end-start);
    cout<<"Time cost for Challenge:"<<duration.count()<<"ms"<<endl;

    //Response
    start=steady_clock::now();
    vector<node> responseNode=generateResponse(fileBlocks, saltsValue[chalMHT], chalLeafNode);
    end=steady_clock::now();
    duration=duration_cast<milliseconds>(end-start);
    cout<<"Time cost for Response:"<<duration.count()<<"ms"<<endl;

    //Verify
    start=steady_clock::now();
    bool isPass=verifyResponse(responseNode, saltsValue[chalMHT], rootNodeofADMHF[chalMHT]);
    end=steady_clock::now();
    duration=duration_cast<milliseconds>(end-start);
    cout<<"Time cost for Verify:"<<duration.count()<<"ms"<<endl;

    if(isPass) cout<<"用户通过了验证！"<<endl;
    else cout<<"用户未通过验证!"<<endl;
    return 0;
}

void blindSig(){    
    string hF = calculateSHA1(fileContent);             //计算文件短哈希

    element_from_hash(h_F, (void*)hF.c_str(),hF.size()*sizeof(char));   //将哈希值映射为椭圆曲线上的元素

    element_init_Zr(q, pairing);
    element_init_Zr(q_inv, pairing);

    element_init_G1(F_p, pairing);
    element_init_G1(alpha_p, pairing);
    element_init_G1(alpha, pairing);

    element_random(q);
    element_invert(q_inv, q);

    //F_p = h_F * q
    element_mul_zn(F_p, h_F, q);

    //alpha_p = F_p * r
    element_mul_zn(alpha_p, F_p, r);

    //alpha = alpha_p * q_inv
    element_mul_zn(alpha, alpha_p, q_inv);

    //tmp1 = e( alpha, g )
    //tmp2 = e( h_F, g1 )
    pairing_apply(tmp1, alpha, g, pairing);
    pairing_apply(tmp2, h_F, g1, pairing);

    if(element_cmp(tmp1,tmp2)){
        cout<<"Verify Failed!"<<endl;
        return;
    }
}

void keyGen(){
    // 初始化pairing
    char param[1024];
    size_t count = fread(param, 1, 1024, stdin);
    if(!count) pbc_die("input error!");
    pairing_init_set_buf(pairing, param, count);

    
    element_init_G2(g, pairing);
    element_init_G2(g1, pairing);
    element_init_G2(pk, pairing);

    element_init_G1(h_F, pairing);

    element_init_GT(tmp1, pairing);
    element_init_GT(tmp2, pairing);

    element_init_Zr(r, pairing);
    element_init_Zr(s, pairing);
    
    element_random(g);  //为G2的生成元g赋值

    element_random(r);  //生成CSP私钥
    element_pow_zn(g1, g, r);

    element_random(s);  //用户
    element_pow_zn(pk, g, s);   //用户公钥
}


void outerLayerDecrypt(){
    //3个双线性映射的结果
    element_t pair1, pair2, pair3, res1, res2, res;

    element_init_GT(pair1, pairing);
    element_init_GT(pair2, pairing);
    element_init_GT(pair3, pairing);
    element_init_GT(res1, pairing);
    element_init_GT(res2, pairing);
    element_init_GT(res, pairing);

    pairing_apply(pair1, C3, pk, pairing);
    pairing_apply(pair2, d1, C1, pairing);
    element_div(res,ZL,pair2);

    pairing_apply(pair3, d2, C1, pairing);

    element_mul(res1, C2, pair1);
    element_mul(res2, pair2, pair3);
    element_div(res, res1, res2);
    
    element_to_mpz(hexCi_mpz, res);

    valueToMessage(hexCi,hexCi_mpz);
    // cout<<"解密外层加密:"<<hexCi<<endl;
}

void outerLayerEncrypt(string hexCiphertext){
    //非流行文件进行双层加密
 
    element_init_G2(C1, pairing);
    element_init_G2(g_p, pairing);
    element_init_G2(h, pairing);
    element_init_G2(C3, pairing);
    element_init_G2(d1, pairing);
    element_init_G2(d2, pairing);

    element_init_GT(Z, pairing);
    element_init_GT(C2, pairing);
    element_init_GT(ZL, pairing);

    element_init_Zr(L, pairing);

    element_random(g_p);
    element_random(L);
    element_random(h);

    //计算 C1 = g^L
    element_pow_zn(C1, g, L);

    //计算 C2 = hexCi_ele * Z^L   Z = e(g1,g_p)
    pairing_apply(Z, g1, g_p, pairing);
    element_pow_zn(ZL, Z, L);

    //将明文消息映射到群上
    mpz_init(hexCi_mpz);
    element_init_GT(hexCi_ele, pairing);
    messageToValue((char *)hexCiphertext.c_str(), hexCi_mpz, hexCi_dec);
    hexCi = "[" + hexCi_dec + ",0]";
    element_set_str(hexCi_ele, hexCi.c_str(), 10);  //将字符串形式的数值赋值给椭圆曲线上的元素

    element_mul(C2, hexCi_ele, ZL);

    //计算 C3 = (g1 * h)^L
    element_pow2_zn(C3, g1, L, h, L);

    //计算 d1 = g_p ^r
    element_pow_zn(d1, g_p, r);

    //计算 d2 = (g1 * h)^s
    element_pow2_zn(d2, g1, s, h, s);
}

bool verifyResponse(vector<node> responseNodeSet, string salt, string realRootNode)
{
    if(responseNodeSet.size()==1) return responseNodeSet[0].content==realRootNode;

    string content=sha256(responseNodeSet[0].content+responseNodeSet[1].content+salt);

    for(int i=2;i<responseNodeSet.size();++i){
        if(responseNodeSet[i].isLeft){
            content=sha256(responseNodeSet[i].content+content+salt);
        }else{
            content=sha256(content+responseNodeSet[i].content+salt);
        }
    }
    return content==realRootNode;
}   

vector<node> generateResponse(vector<string> fileBlocks, string salt, int challengeLeafNode)
{
    vector<node> res;
    vector<string> hashList;
    queue<string> hashQueue;

    int leafNodeNum=fileBlocks.size();

    if(leafNodeNum==1){
        res.push_back({ sha256(fileBlocks[0]+salt), 1 });
        return res;
    }
    // cout<<"challengeLeafNode:"<<challengeLeafNode<<' '<<"leafNodeNum:"<<leafNodeNum<<endl;
    // cout<<"generate response:"<<endl;

    //将叶子结点入队
    for(int i=0;i<leafNodeNum;++i){
        string content=sha256(fileBlocks[i]+salt);
        hashQueue.push(content);
        hashList.push_back(content);
        // cout<<"index:"<<i<<' '<<content<<endl;
    }

    //最底层的节点
    if(challengeLeafNode % 2==0){
        res.push_back({ hashList[challengeLeafNode] , 1});
        res.push_back({ hashList[challengeLeafNode+1], 0});
        // cout<<"diceng:"<<' '<<hashList[challengeLeafNode]<<' '<<1<<endl;
        // cout<<hashList[challengeLeafNode+1]<<' '<<0<<endl;
    } 
    else{
        res.push_back({ hashList[challengeLeafNode-1], 1});
        res.push_back({ hashList[challengeLeafNode], 0});
        // cout<<"diceng:"<<' '<<hashList[challengeLeafNode-1]<<' '<<1<<endl;
        // cout<<hashList[challengeLeafNode]<<' '<<0<<endl;
    } 
    challengeLeafNode/=2;
    hashList.clear();

    while(hashQueue.size()>2){
        int cnt=hashQueue.size();
        if(cnt%2==1){
            hashQueue.push(hashQueue.back());
            hashList.push_back(hashQueue.back());
            // cout<<"back1:"<<' '<<hashQueue.back()<<endl;
            cnt++;
        }

        hashList.clear();

        queue<string> newQueue;
        for(int i=0;i<cnt;i+=2){
            string lft=hashQueue.front();
            hashQueue.pop();
            string rght=hashQueue.front();
            hashQueue.pop();
            string content=sha256(lft+rght+salt);

            // cout<<content<<endl;
            newQueue.push(content);
            hashList.push_back(content);
        }

        if(newQueue.size()%2==1){
            newQueue.push(newQueue.back());
            hashList.push_back(newQueue.back());
            // cout<<"back2:"<<' '<<newQueue.back()<<endl;
        }

        if(challengeLeafNode%2==0) {
            res.push_back({ hashList[challengeLeafNode+1], 0 });
            // cout<<hashList[challengeLeafNode+1]<<' '<<0<<' '<<challengeLeafNode<<endl;
        }
        else{
            res.push_back({ hashList[challengeLeafNode-1], 1 });
            // cout<<hashList[challengeLeafNode-1]<<' '<<1<<endl;
        }


        challengeLeafNode/=2;
        hashQueue=newQueue;
    }
    return res;
}

int calculateNumBytes(int n) {
    // 计算最高位的位置
    int numBits = 0;
    while (n) {
        n >>= 1;
        ++numBits;
    }

    // 计算所需的字节数
    return (numBits + CHAR_BIT - 1) / CHAR_BIT;
}

// 生成 [0, n] 范围内的随机数
int generateRandomNumber(int n) {
    if (n < 0) {
        // 处理非法输入
        return -1;
    }

    // 计算所需字节数
    int numBytes = calculateNumBytes(n);

    // 申请足够的字节空间
    vector<unsigned char> randomBytes(numBytes);

    // 生成加密强度的随机字节
    if (RAND_bytes(randomBytes.data(), numBytes) != 1) {
        // 处理生成随机数失败的情况
        return -1;
    }

    // 将字节转换为整数
    unsigned int randomNumber = 0;
    for (int i = 0; i < numBytes; ++i) {
        randomNumber = (randomNumber << CHAR_BIT) | randomBytes[i];
    }

    // 将随机数映射到 [0, n] 范围
    return static_cast<int>(randomNumber % (n + 1));
}

void messageToValue(const string& message, mpz_t message_mpz, string &m) {
    // 将16进制字符串转换为mpz_t类型
    mpz_set_str(message_mpz, message.c_str(), 16);

    // 获取转换后的数字的10进制字符串表示
    char *tmp = mpz_get_str(nullptr, 10, message_mpz);
    m = string(tmp);
    // 释放GMP分配的内存
    free(tmp);
}

void valueToMessage(string &message, mpz_t message_mpz) {
    // 将mpz_t类型的10进制数字转换为16进制字符串
    char *tmp = mpz_get_str(nullptr, 16, message_mpz);
    message = string(tmp);
    // 释放GMP分配的内存
    free(tmp);
}

vector<string> generateRandomSalts(int nMHTs, int size) {
    vector<string> salts;

    // 设置随机数生成器
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<int> dis(65, 90); // 生成范围在 [65, 90] 内的整数

    // 生成 nMHTs 个随机盐值
    for (int i = 0; i < nMHTs; ++i) {
        string salt;
        // 生成 size 个随机字符并添加到盐值字符串中
        for (int j = 0; j < size; ++j) {
            unsigned char randomChar = static_cast<unsigned char>(dis(gen));
            salt.push_back(randomChar);
        }
        // 将盐值字符串添加到向量中
        salts.push_back(salt);
    }

    return salts;
}

int calculateMHTNum(int x) {
    double y = max(8.22 / (1 + exp(2.45 - (488.69 / x))), double(1));
    return int(y);
}

//根据分块的密文生成MHT，返回根节点的值
string buildMerkleHashTree(vector<string> fileBlocks, string salt)
{
    queue<string> hashQueue;
    treeLevel=1;
    int leafNodeNum=fileBlocks.size();
    // cout<<"build MHT:"<<endl;
    //先把叶子结点全都入队
    for( int i = 0 ; i < leafNodeNum ; ++i ){
        string content = sha256(fileBlocks[i] + salt);
        hashQueue.push(content);
        // cout<<content<<endl;
    }

    while( hashQueue.size() > 1 )
    {
        int cnt = hashQueue.size();

        if( cnt % 2 == 1 )
        {
            hashQueue.push(hashQueue.back());
            cnt++;
            // cout<<hashQueue.back()<<endl;
        }

        queue<string> newQueue;

        for( int i = 0 ; i < cnt ; i+=2 )
        {
            string left = hashQueue.front();
            hashQueue.pop();
            string right = hashQueue.front();
            hashQueue.pop();
            string content = sha256( left + right + salt );
            // cout<<content<<endl;
            newQueue.push(content);
        }

        hashQueue = newQueue;
        treeLevel++;
    }

    return hashQueue.front();
}

vector<string> splitStringIntoBlocks(const string& inputString, int blockSize) {
    vector<string> blocks;

    // 遍历字符串
    for (size_t i = 0; i < inputString.length(); i += blockSize) {
        // 获取当前块
        string block = inputString.substr(i, blockSize);

        // 将当前块添加到数组或列表
        blocks.push_back(block);
    }

    return blocks;
}

//字节数组 --> 16进制字符串
string toHexString(const vector<unsigned char>& data) {
    stringstream ss;
    ss << hex << setfill('0');
    for (unsigned char c : data) {
        ss << setw(2) << static_cast<int>(c);
    }
    return ss.str();
}

//16进制字符串 --> 字节数组
vector<unsigned char> fromHexString(const string& hexString) {
    vector<unsigned char> result;

    // 每两个字符表示一个字节
    for (size_t i = 0; i < hexString.length(); i += 2) {
        // 提取两个字符
        string byteString = hexString.substr(i, 2);

        // 将两个字符转换为十六进制数值
        unsigned char byte = static_cast<unsigned char>(stoi(byteString, nullptr, 16));

        // 将转换后的字节添加到结果向量中
        result.push_back(byte);
    }

    return result;
}

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

vector<unsigned char> aes_encrypt(const string &plaintext, const string &keyString, const string &ivString) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    unsigned char *key = reinterpret_cast<unsigned char*>(const_cast<char*>(keyString.data()));
    unsigned char *iv = reinterpret_cast<unsigned char*>(const_cast<char*>(ivString.data()));

    /* 创建和初始化 cipher 上下文 */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* 初始化加密操作 */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /* 提供明文进行加密 */
    if(1 != EVP_EncryptUpdate(ctx, &ciphertext[0], &len, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()))
        handleErrors();
    ciphertext_len = len;

    /* 完成加密过程 */
    if(1 != EVP_EncryptFinal_ex(ctx, &ciphertext[0] + len, &len)) handleErrors();
    ciphertext_len += len;

    /* 调整密文大小 */
    ciphertext.resize(ciphertext_len);

    /* 清理 */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

string aes_decrypt(const vector<unsigned char> &ciphertext, const string &keyString, const string &ivString) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    vector<unsigned char> plaintext(ciphertext.size());
    unsigned char *key = reinterpret_cast<unsigned char*>(const_cast<char*>(keyString.data()));
    unsigned char *iv = reinterpret_cast<unsigned char*>(const_cast<char*>(ivString.data()));

    /* 创建和初始化 cipher 上下文 */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* 初始化解密操作 */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /* 提供密文进行解密 */
    if(1 != EVP_DecryptUpdate(ctx, &plaintext[0], &len, &ciphertext[0], ciphertext.size()))
        handleErrors();
    plaintext_len = len;

    /* 完成解密过程 */
    if(1 != EVP_DecryptFinal_ex(ctx, &plaintext[0] + len, &len)) handleErrors();
    plaintext_len += len;

    /* 调整明文大小 */
    plaintext.resize(plaintext_len);

    /* 清理 */
    EVP_CIPHER_CTX_free(ctx);

    return string(reinterpret_cast<const char*>(&plaintext[0]), plaintext_len);
}

string sha256(const string str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);

    stringstream ss;
    for(unsigned char i : hash) {
        ss << hex << setw(2) << setfill('0') << (int)i;
    }
    return ss.str();
}


string sha256(element_t& input) {
    unsigned char hash[1000*SHA256_DIGEST_LENGTH];
    char hash_hex[2000 * SHA256_DIGEST_LENGTH + 1];

    element_to_bytes(hash, input);
    
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, hash, SHA256_DIGEST_LENGTH);
    SHA256_Final(hash, &sha256);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        sprintf(&hash_hex[i * 2], "%02x", hash[i]);
    }
    return hash_hex;
}

string calculateSHA1(const string& data) {
    SHA_CTX shaContext;
    SHA1_Init(&shaContext);
    SHA1_Update(&shaContext, data.c_str(), data.size());

    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1_Final(hash, &shaContext);

    stringstream ss;
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

string readFileInChunks(const string &filePath) {
    ifstream inputFile(filePath, ios::binary);

    if (!inputFile.is_open()) {
        cerr << "Error opening file: " << filePath << endl;
        return "";
    }

    vector<char> buffer(BUFFER_SIZE);
    string fileContent;

    while (!inputFile.eof()) {
        inputFile.read(buffer.data(), buffer.size());
        fileContent.append(buffer.data(), static_cast<size_t>(inputFile.gcount()));
    }

    inputFile.close();

    return fileContent;
}