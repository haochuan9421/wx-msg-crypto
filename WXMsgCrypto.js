const crypto = require("crypto");

class PKCS7 {
  /**
   * 删除补位
   * @param {String} text 解密后的明文
   */
  decode(text) {
    let pad = text[text.length - 1];
    if (pad < 1 || pad > 32) {
      pad = 0;
    }
    return text.slice(0, text.length - pad);
  }
  /**
   * 填充补位
   * @param {String} text 需要进行填充补位的明文
   */
  encode(text) {
    const blockSize = 32;
    const textLength = text.length;
    // 计算需要填充的位数
    const amountToPad = blockSize - (textLength % blockSize);
    const result = Buffer.alloc(amountToPad);
    result.fill(amountToPad);
    return Buffer.concat([text, result]);
  }
}

class WXMsgCrypto {
  /**
   * 【微信公众号后台 - 开发 - 基本配置】 或者 【微信开放平台 - 管理中心 - 第三方平台】
   * @param {String} token          令牌(Token)
   * @param {String} encodingAESKey 消息加解密密钥
   * @param {String} appId          公众号的AppId
   */
  constructor(token, encodingAESKey, appId) {
    if (!token || !encodingAESKey || !appId) {
      throw new Error("please check arguments");
    }
    this.token = token;
    this.appId = appId;

    let AESKey = Buffer.from(encodingAESKey + "=", "base64");
    if (AESKey.length !== 32) {
      throw new Error("encodingAESKey invalid");
    }
    this.key = AESKey;
    this.iv = AESKey.slice(0, 16);
    this.pkcs7 = new PKCS7();
  }
  /**
   * 获取签名
   * @param {String} timestamp    时间戳
   * @param {String} nonce        随机数
   * @param {String} encrypt      加密后的文本
   */
  getSignature(timestamp, nonce, encrypt) {
    const sha = crypto.createHash("sha1");

    const arr = [this.token, timestamp, nonce];
    if (encrypt) {
      arr.push(encrypt);
    }
    arr.sort();
    sha.update(arr.join(""));
    return sha.digest("hex");
  }
  /**
   * 对密文进行解密
   * @param {String} text    待解密的密文
   */
  decrypt(text) {
    // 创建解密对象，AES采用CBC模式，数据采用PKCS#7填充；IV初始向量大小为16字节，取AESKey前16字节
    const decipher = crypto.createDecipheriv("aes-256-cbc", this.key, this.iv);
    decipher.setAutoPadding(false);

    let deciphered = Buffer.concat([
      decipher.update(text, "base64"),
      decipher.final()
    ]);

    deciphered = this.pkcs7.decode(deciphered);
    // 算法：AES_Encrypt[random(16B) + msg_len(4B) + msg + $CorpID]
    // 去除16位随机数
    const content = deciphered.slice(16);
    const length = content.slice(0, 4).readUInt32BE(0);

    return {
      message: content.slice(4, length + 4).toString(),
      appId: content.slice(length + 4).toString()
    };
  }
  /**
   * 对明文进行加密
   * 算法：Base64_Encode(AES_Encrypt[random(16B) + msg_len(4B) + msg + $appId])
   * @param {String} text    待加密明文文本
   */
  encrypt(text) {
    // 16B 随机字符串
    const randomString = crypto.pseudoRandomBytes(16);

    const msg = Buffer.from(text);
    // 获取4B的内容长度的网络字节序
    const msgLength = Buffer.alloc(4);
    msgLength.writeUInt32BE(msg.length, 0);

    const id = Buffer.from(this.appId);

    const bufMsg = Buffer.concat([randomString, msgLength, msg, id]);

    // 对明文进行补位操作
    const encoded = this.pkcs7.encode(bufMsg);

    // 创建加密对象，AES采用CBC模式，数据采用PKCS#7填充；IV初始向量大小为16字节，取AESKey前16字节
    const cipher = crypto.createCipheriv("aes-256-cbc", this.key, this.iv);
    cipher.setAutoPadding(false);

    const cipheredMsg = Buffer.concat([cipher.update(encoded), cipher.final()]);

    return cipheredMsg.toString("base64");
  }
}

module.exports = WXMsgCrypto;
