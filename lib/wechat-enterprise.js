/**
 *Intro:
 *Author:shine
 *Date:2018/3/27
 */


const xml2js = require('xml2js');
const ejs = require('ejs');
const WXBizMsgCrypt = require('wechat-crypto');

/*!
 * 响应模版
 */
const tpl = ['<xml>',
    '<ToUserName><![CDATA[<%-toUsername%>]]></ToUserName>',
    '<FromUserName><![CDATA[<%-fromUsername%>]]></FromUserName>',
    '<CreateTime><%=createTime%></CreateTime>',
    '<MsgType><![CDATA[<%=msgType%>]]></MsgType>',
    '<% if (msgType === "news") { %>',
    '<ArticleCount><%=content.length%></ArticleCount>',
    '<Articles>',
    '<% content.forEach(function(item){ %>',
    '<item>',
    '<Title><![CDATA[<%-item.title%>]]></Title>',
    '<Description><![CDATA[<%-item.description%>]]></Description>',
    '<PicUrl><![CDATA[<%-item.picUrl || item.picurl || item.pic %>]]></PicUrl>',
    '<Url><![CDATA[<%-item.url%>]]></Url>',
    '</item>',
    '<% }); %>',
    '</Articles>',
    '<% } else if (msgType === "music") { %>',
    '<Music>',
    '<Title><![CDATA[<%-content.title%>]]></Title>',
    '<Description><![CDATA[<%-content.description%>]]></Description>',
    '<MusicUrl><![CDATA[<%-content.musicUrl || content.url %>]]></MusicUrl>',
    '<HQMusicUrl><![CDATA[<%-content.hqMusicUrl || content.hqUrl %>]]></HQMusicUrl>',
    '</Music>',
    '<% } else if (msgType === "voice") { %>',
    '<Voice>',
    '<MediaId><![CDATA[<%-content.mediaId%>]]></MediaId>',
    '</Voice>',
    '<% } else if (msgType === "image") { %>',
    '<Image>',
    '<MediaId><![CDATA[<%-content.mediaId%>]]></MediaId>',
    '</Image>',
    '<% } else if (msgType === "video") { %>',
    '<Video>',
    '<MediaId><![CDATA[<%-content.mediaId%>]]></MediaId>',
    '<Title><![CDATA[<%-content.title%>]]></Title>',
    '<Description><![CDATA[<%-content.description%>]]></Description>',
    '</Video>',
    '<% } else if (msgType === "transfer_customer_service") { %>',
    '<% if (content && content.kfAccount) { %>',
    '<TransInfo>',
    '<KfAccount><![CDATA[<%-content.kfAccount%>]]></KfAccount>',
    '</TransInfo>',
    '<% } %>',
    '<% } else { %>',
    '<Content><![CDATA[<%-content%>]]></Content>',
    '<% } %>',
    '</xml>'].join('');

/*!
 * 编译过后的模版
 */
const compiled = ejs.compile(tpl);

const wrapTpl = '<xml>' +
    '<Encrypt><![CDATA[<%-encrypt%>]]></Encrypt>' +
    '<MsgSignature><![CDATA[<%-signature%>]]></MsgSignature>' +
    '<TimeStamp><%-timestamp%></TimeStamp>' +
    '<Nonce><![CDATA[<%-nonce%>]]></Nonce>' +
    '</xml>';

const encryptWrap = ejs.compile(wrapTpl);

const load = (stream, callback) => {
    const buffers = [];
    stream.on('data', (trunk) => {
        buffers.push(trunk);
    });
    stream.on('end', () => {
        callback(null, Buffer.concat(buffers));
    });
    stream.once('error', callback);
};

/*!
 * 将xml2js解析出来的对象转换成直接可访问的对象
 */
const formatMessage = (result) => {
    const message = {};
    if (typeof result === 'object') {
        for (const key in result) {
            if (!Array.isArray(result[key]) || result[key].length === 0) {
                continue; // eslint-disable-line
            }
            if (result[key].length === 1) {
                const val = result[key][0];
                if (typeof val === 'object') {
                    message[key] = formatMessage(val);
                } else {
                    message[key] = (val || '').trim();
                }
            } else {
                message[key] = [];
                result[key].forEach((item) => {
                    message[key].push(formatMessage(item));
                });
            }
        }
    }
    return message;
};

/*!
 * 将回复消息封装成xml格式
 */
const replyXML = (content, fromUsername, toUsername) => {
    const info = {};
    let type = 'text';
    info.content = content || '';
    if (Array.isArray(content)) {
        type = 'news';
    } else if (typeof content === 'object') {
        if (content.hasOwnProperty('type')) {
            type = content.type;
            info.content = content.content;
        } else {
            type = 'music';
        }
    }
    info.msgType = type;
    info.createTime = new Date().getTime();
    info.toUsername = toUsername;
    info.fromUsername = fromUsername;
    return compiled(info);
};

/**
 * 微信自动回复平台的内部的Handler对象
 * @param {Object} config 企业号的开发者配置对象
 * @param {Function} handle handle对象
 *
 * config:
 * ```
 * {
 *   token: '',          // 公众平台上，开发者设置的Token
 *   encodingAESKey: '', // 公众平台上，开发者设置的EncodingAESKey
 *   corpId: '',         // 企业号的CorpId
 * }
 * ```
 */
class Handler {
    constructor(config, req, res, handle) {
        this.config = config;
        this.cryptor = new WXBizMsgCrypt(config.token, config.encodingAESKey, config.corpId);
        this.handle = handle;
        this.weixin = false;
        this.res = res;
        this.req = req;
        this.end = false;
        this._init();
    }

    _endRes(code, response) {
        this.end = true;
        this.res.writeHead(code);
        this.res.end(response);
    }

    _init() {
        const self = this;
        const method = self.req.method;
        const signature = self.req.query.msg_signature;
        const timestamp = self.req.query.timestamp;
        const nonce = self.req.query.nonce;
        if (method === 'GET') {
            const echostr = self.req.query.echostr;
            if (signature !== self.cryptor.getSignature(timestamp, nonce, echostr)) {
                self._endRes(401, 'Invalid signature');
                return;
            }
            const result = self.cryptor.decrypt(echostr);
            self._endRes(200, result.message);
        } else if (method === 'POST') {
            load(self.req, (err, buf) => {
                if (err) {
                    self.err = err;
                    return;
                }
                const xml = buf.toString('utf-8');
                if (!xml) {
                    self._endRes(500, 'body is empty');
                    return;
                }
                xml2js.parseString(xml, { trim: true }, (err2, result) => {
                    if (err2) {
                        self._endRes(500, `BadMessage${err2.name}`);
                        return;
                    }
                    const xml2 = formatMessage(result.xml);
                    const encryptMessage = xml2.Encrypt;
                    if (signature !== self.cryptor.getSignature(timestamp, nonce, encryptMessage)) {
                        self._endRes(401, 'Invalid signature');
                        return;
                    }
                    const decrypted = self.cryptor.decrypt(encryptMessage);
                    const messageWrapXml = decrypted.message;
                    if (messageWrapXml === '') {
                        self._endRes(401, 'Invalid corpid');
                        return;
                    }
                    xml2js.parseString(messageWrapXml, { trim: true }, (err3, result2) => {
                        if (err3) {
                            self._endRes(500, `BadMessage${err3.name}`);
                            return;
                        }
                        self.weixin = formatMessage(result2.xml);
                    });
                });
            });
        } else {
            self._endRes(501, 'Not Implemented');
        }
    }

    reply(content) {
        this.res.writeHead(200);
        // 响应空字符串，用于响应慢的情况，避免微信重试
        if (!content) {
            return this.res.end();
        }
        const xml = replyXML(content, this.weixin.ToUserName, this.weixin.FromUserName);
        const cryptor = this.cryptor;
        const wrap = {};
        wrap.encrypt = cryptor.encrypt(xml);
        wrap.nonce = parseInt((Math.random() * 100000000000), 10);
        wrap.timestamp = new Date().getTime();
        wrap.signature = cryptor.getSignature(wrap.timestamp, wrap.nonce, wrap.encrypt);
        return this.res.end(encryptWrap(wrap));
    }
}

module.exports = Handler;