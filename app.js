const Koa = require("koa");
const Router = require("koa-router");
const bodyParser = require("koa-bodyparser");
const xml2js = require("xml2js");
const WXMsgCrypto = require("./WXMsgCrypto");

const app = new Koa();
const router = new Router();
// https://www.npmjs.com/package/xml2js
const xmlparser = new xml2js.Parser({ explicitArray: false });
// https://github.com/koajs/bodyparser
app.use(
  bodyParser({
    // https://github.com/hapijs/qs/blob/master/lib/parse.j
    queryString: {
      arrayLimit: 100,
      depth: 5,
      parameterLimit: 1000
    },
    enableTypes: ["json", "form", "text"],
    extendTypes: {
      text: ["text/xml", "application/xml"]
    }
  })
);

// 打印日志，方便 DEBUG
router.all("*", async (ctx, next) => {
  console.log(`<-------------${new Date().toString()}--------------->`);
  console.log(ctx.method, ctx.request.path);
  console.log("\nheaders", JSON.stringify(ctx.headers, null, 2));
  console.log("\nquery", JSON.stringify(ctx.request.query, null, 2));
  console.log("\nbody", JSON.stringify(ctx.request.body, null, 2));
  await next();
});

router.get("/", async ctx => {
  ctx.body = "OK";
});

// 可以在【微信公众号后台 - 开发 - 基本配置】 或者 【微信开放平台 - 管理中心 - 第三方平台】找到，此处已脱敏
const Token = '********************************';
const EncodingAESKey = '*******************************************';
const Appid = 'wx****************';

const wxmc = new WXMsgCrypto(Token, EncodingAESKey, Appid);

router.all(
  "/wx_third/notify",
  async (ctx, next) => {
    const query = ctx.request.query;
    const xmlbody = await xmlparser.parseStringPromise(ctx.request.body);
    const encryptTxt = xmlbody.xml.Encrypt;
    const msgSignature = wxmc.getSignature(
      query.timestamp,
      query.nonce,
      encryptTxt
    );
    const signature = wxmc.getSignature(query.timestamp, query.nonce);

    console.log("\nxmlbody", xmlbody);
    console.log("\nmsgSignature", msgSignature);
    console.log("\nsignature", signature);

    if (msgSignature === query.msg_signature && signature === query.signature) {
      console.log("\n请求合法，校验通过");
      ctx.encryptTxt = encryptTxt;
      await next();
    } else {
      console.log("\n请求不合法");
      ctx.state = 403;
      ctx.body = "Not Legal";
    }
  },
  async ctx => {
    const xmlSource = wxmc.decrypt(ctx.encryptTxt);
    console.log("\n解密出 xmlSource:", xmlSource);
    const xmlJSON = await xmlparser.parseStringPromise(xmlSource.message);
    console.log("\n转换成 JSON:", xmlJSON);

    // 加密一段消息并返回
    const timestamp = Math.ceil(Date.now() / 1000);
    const nonce = Math.random()
      .toString()
      .slice(-9);

    const msg = `<xml>
        <ToUserName><![CDATA[${xmlJSON.xml.ToUserName}]]></ToUserName>
        <FromUserName><![CDATA[${xmlJSON.xml.FromUserName}]]></FromUserName>
        <CreateTime>${timestamp}</CreateTime>
        <MsgType><![CDATA[ENTER]]></MsgType>
      </xml>`;
    const encryptTxt = wxmc.encrypt(msg);
    const msgSignature = wxmc.getSignature(timestamp, nonce, encryptTxt);
    result = `<xml>
      <Encrypt><![CDATA[${encryptTxt}]]></Encrypt>
      <MsgSignature>${msgSignature}</MsgSignature>
      <TimeStamp>${timestamp}</TimeStamp>
      <Nonce>${nonce}</Nonce>
    </xml>`;
    ctx.response.set("Content-Type", "application/xml");
    ctx.body = result;
  }
);

app.use(router.routes(), router.allowedMethods());

app.listen(7001, () => {
  console.log(`应用已启动: http://127.0.0.1:7001`);
});
