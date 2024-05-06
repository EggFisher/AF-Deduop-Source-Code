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

#define PBC_DEBUG

using namespace std;
using namespace chrono;

struct node{
    string content;
    int isLeft;
};

const int popThresh = 7;    //流行度阈值
const int saltsLen = 8;     //随机盐值长度8B
const int fileBlockSize = 1024;   //生成MHT时文件分块大小
const int encryptFileBlockSize = 1024 * 16;  //进行双层加密时文件分块大小
constexpr streamsize BUFFER_SIZE = 1024 * 1024;  // 1MB buffer size
int treeLevel;
const string filePath = "file256MB.bin";
string ivString = "0123456789012345"; // AES-CBC 需要 16 字节长的 IV

pairing_t pairing;
element_t g, h_F;
element_t r, s, g1, pk;
element_t tmp1, tmp2;
element_t C1, C2, C3, C4, C5;
element_t g_p, h, L;
element_t d1, d2, Z, ZL;
string hexCiphertext, fileContent, K1, fileTag, plaintext;
element_t q, q_inv, F_p, alpha_p, alpha;
int nLeaves, nMHTs;
vector<string> fileBlocks, saltsValue, rootNodeofADMHF, outerLayerCiphertext;
vector<unsigned char> ciphertext;

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
string hex_xor(const string& hex1, const string& hex2);
string element_to_string(element_t element);
void outerLayerEncrypt();
string outerLayerDecrypt(string str);
void keyGen();
void blindSig();
void initialUpload();
void subsequentUpload();
void dataDeduplication();
void fileDownload();

int main(){
    cout<<filePath<<endl;

    // 初始化pairing
    char param[1024];
    size_t count = fread(param, 1, 1024, stdin);
    if(!count) pbc_die("input error!");
    pairing_init_set_buf(pairing, param, count);

    //生成密钥
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

    //文件加密
    start=steady_clock::now();  //计算加密密钥 K1 = H(alpha)

    K1=sha256(alpha);
    ciphertext = aes_encrypt(fileContent, K1, ivString);
    hexCiphertext = toHexString(ciphertext); //16进制密文

    end=steady_clock::now();
    duration=duration_cast<milliseconds>(end-start);
    cout<<"Time cost for FileEncryption:"<<duration.count()<<"ms"<<endl;

    //生成文件标签 fileTag = H(ciphertext)
    start=steady_clock::now();
    fileTag = sha256(hexCiphertext);
    end=steady_clock::now();
    duration=duration_cast<milliseconds>(end-start);
    cout<<"Time cost for FileTagGen:"<<duration.count()<<"ms"<<endl;

    bool isInitialUser=1;
    if(isInitialUser){
        initialUpload();
    }else{
        subsequentUpload();
    }
    
    return 0;
}

void subsequentUpload(){
    //Challenge
    auto start=steady_clock::now();
    int chalMHT=generateRandomNumber(nMHTs-1);
    int chalLeafNode=generateRandomNumber(nLeaves-1);
    auto end=steady_clock::now();
    auto duration=duration_cast<milliseconds>(end-start);
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
    else{
        cout<<"用户未通过验证!"<<endl;
        exit(0);
    } 

    int cntF=7;
    if(cntF==popThresh) dataDeduplication();
}

void fileDownload(){
    int tagPop=0;

    auto start=steady_clock::now();
    if(tagPop==1){
        //非流行数据，需要双层解密
        for(auto ele:outerLayerCiphertext){
            hexCiphertext+=outerLayerDecrypt(ele);
        }
    }

    ciphertext=fromHexString(hexCiphertext);
    aes_decrypt(ciphertext,K1,ivString);

    auto end=steady_clock::now();
    auto duration=duration_cast<milliseconds>(end-start);
    cout<<"Time cost for FileDownload:"<<duration.count()<<"ms"<<endl;
}

void dataDeduplication(){
    //对外层进行解密
    for(auto ele:outerLayerCiphertext){
        outerLayerDecrypt(ele);
    }
}

void initialUpload(){
    //进行双层加密
    auto start=steady_clock::now();
    outerLayerEncrypt();
    string strC5=element_to_string(C5);

    //密文
    vector<string> encryptFileBlocks = splitStringIntoBlocks(hexCiphertext, encryptFileBlockSize);
    for(auto ele:encryptFileBlocks){
        string ciphertext=hex_xor(strC5,ele);
        outerLayerCiphertext.push_back(ciphertext);
    }

    string strL=element_to_string(L);
    string fileHashVal=sha256(fileContent);
    string tao_F = hex_xor(strL,fileHashVal);   //加密密钥

    auto end=steady_clock::now();
    auto duration=duration_cast<milliseconds>(end-start);
    cout<<"Time cost for OuterLayerEncryption:"<<duration.count()<<"ms"<<endl;

    //构建ADMHF
    fileBlocks = splitStringIntoBlocks(hexCiphertext, fileBlockSize);
    nLeaves = fileBlocks.size();

    nMHTs = calculateMHTNum(nLeaves);

    saltsValue = generateRandomSalts(nMHTs, saltsLen);

    //生成 ADMHF (nMHTs个)
    start=steady_clock::now();
    
    for( int i=0; i<nMHTs; ++i ){
        rootNodeofADMHF.push_back(buildMerkleHashTree(fileBlocks, saltsValue[i]));
    }
    end=steady_clock::now();
    duration=duration_cast<milliseconds>(end-start);
    cout<<"Time cost for ADMHF Generation:"<<duration.count()<<"ms"<<endl;
}

// 对两个十六进制字符串进行异或操作
string hex_xor(const string& hex1, const string& hex2) {
    // 确定结果的长度为两个输入字符串中较长的那个
    size_t max_length = max(hex1.size(), hex2.size());
    string result(max_length, '0');
    
    // 从后往前逐位进行异或操作
    for (int i = max_length - 1; i >= 0; --i) {
        char hex1_char = (i < hex1.size()) ? hex1[i] : '0';
        char hex2_char = (i < hex2.size()) ? hex2[i] : '0';
        
        // 将十六进制字符转换为对应的整数值
        int val1 = (hex1_char >= '0' && hex1_char <= '9') ? hex1_char - '0' : hex1_char - 'A' + 10;
        int val2 = (hex2_char >= '0' && hex2_char <= '9') ? hex2_char - '0' : hex2_char - 'A' + 10;
        
        // 计算异或结果
        int xor_result = val1 ^ val2;
        
        // 将整数值转换为对应的十六进制字符
        char hex_result = (xor_result < 10) ? ('0' + xor_result) : ('A' + xor_result - 10);
        
        // 存储结果
        result[i] = hex_result;
    }
    
    return result;
}

string element_to_string(element_t element) {
    char *buf;
    size_t len = 1024 *1024; // 初始大小为1024，可以根据需要调整
    buf = (char *)malloc(len);
    element_snprint(buf, len, C5);
    string str(buf);
    free(buf);
    return str;
}

//进行盲签名
void blindSig(){    
    string hF = calculateSHA1(fileContent);             //计算文件短哈希

    element_from_hash(h_F, (void*)hF.c_str(),hF.size()*sizeof(char));   //将哈希值映射为椭圆曲线上的元素

    element_init_Zr(q, pairing);
    element_init_Zr(q_inv, pairing);

    element_init_G1(F_p, pairing);
    element_init_G1(alpha_p, pairing);
    element_init_G1(alpha, pairing);

    element_random(q);  //用户随机选择q
    element_invert(q_inv, q);   //求q的逆元

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

//用户和CSP生成公私钥
void keyGen(){
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

    element_random(s);  //用户选取随机数s
    element_pow_zn(pk, g, s);   //用户公钥
}

string outerLayerDecrypt(string ciphertext){
    //3个双线性映射的结果
    element_t pair1, pair2, res1, res2, res;

    element_init_GT(pair1, pairing);
    element_init_GT(pair2, pairing);
    element_init_GT(res1, pairing);
    element_init_GT(res2, pairing);
    element_init_GT(res, pairing);

    pairing_apply(pair1, d2, C1, pairing);
    pairing_apply(pair2, d1, C1, pairing);

    element_mul(res1, pair1, pair2);
    string strRes1=element_to_string(res1);
    // cout<<"解密以后的值:"<<hex_xor(strRes1,ciphertext)<<endl;
}

void outerLayerEncrypt(){
    //非流行文件进行双层加密
 
    element_init_G2(C1, pairing);
    element_init_G2(g_p, pairing);
    element_init_G2(h, pairing);
    element_init_G2(C3, pairing);
    element_init_G2(d1, pairing);
    element_init_G2(d2, pairing);

    element_init_GT(C4, pairing);
    element_init_GT(C5, pairing);
    element_init_GT(Z, pairing);
    element_init_GT(C2, pairing);
    element_init_GT(ZL, pairing);

    element_init_Zr(L, pairing);

    element_random(g_p);
    element_random(L);
    element_random(h);

    //计算 C1 = g^L
    element_pow_zn(C1, g, L);

    //计算 C2 = Z^L   Z = e(g1,g_p)
    pairing_apply(Z, g1, g_p, pairing);
    element_pow_zn(C2, Z, L);

    //计算 C3 = (g1 * h)^L
    element_pow2_zn(C3, g1, L, h, L);

    //计算 d1 = g_p ^r
    element_pow_zn(d1, g_p, r);

    //计算 d2 = (g1 * h)^s
    element_pow2_zn(d2, g1, s, h, s);

    //计算 C4 = e(C3, pk)
    pairing_apply(C4, C3, pk, pairing);

    //计算 C5 = c4*C2
    element_mul(C5, C4, C2);
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