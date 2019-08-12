/**
 * 微信JS-SDK Promise封装
 *
 * 依赖微信js
 * 微信JS-SDK说明文档
 * https://mp.weixin.qq.com/wiki?t=resource/res_main&id=mp1421141115
 *
 * @link https://mp.weixin.qq.com/wiki?t=resource/res_main&id=mp1421141115
 * @link https://github.com/snowdreamtech/jweixin
 *
 */
const fetch = require('node-fetch');

/**
 * 生成签名的随机串 nonceStr
 */
exports.createNonceStr = function () {
    return Math.random().toString(36).substr(2, 15);
};

/**
 * 生成签名的时间戳 timestamp
 */
exports.createTimestamp = function () {
    return parseInt(new Date().getTime() / 1000) + '';
};

/**
 * 签名算法
 *
 * 签名生成规则如下： 参与签名的字段包括noncestr（ 随机字符串）, 有效的jsapi_ticket, timestamp（ 时间戳）,
 * url（ 当前网页的URL， 不包含# 及其后面部分）。 对所有待签名参数按照字段名的ASCII 码从小到大排序（ 字典序） 后，
 * 使用URL键值对的格式（ 即key1 = value1 & key2 = value2…） 拼接成字符串string1。 这里需要注意的是所有参数名均为小写字符。
 * 对string1作sha1加密， 字段名和字段值都采用原始值， 不进行URL 转义。
 *
 * 签名合并排序
 */
exports.raw = function (args) {
    let keys = Object.keys(args);
    keys = keys.sort()
    let newArgs = {};
    keys.forEach(function (key) {
        newArgs[key.toLowerCase()] = args[key];
    });

    let string = '';
    for (let k in newArgs) {
        string += '&' + k + '=' + newArgs[k];
    }
    string = string.substr(1);
    return string;
};

/**
 *
 * 获取access_token
 * https: //mp.weixin.qq.com/wiki?t=resource/res_main&id=mp1421140183
 *
 * grant_type 是 获取access_token填写client_credential
 * appid 是 第三方用户唯一凭证
 * secret 是 第三方用户唯一凭证密钥， 即appsecret
 *
 * @param params
 */
exports.getAccessTokenAsync = function (params) {
    return new Promise(function (resolve, reject) {
        if (!params) {
            reject(new Error('params参数不能为空'));
        }

        if (!params.grant_type) {
            reject(new Error('params参数grant_type不能为空'));
        }

        if (!params.appid) {
            reject(new Error('params参数appid不能为空'));
        }

        if (!params.secret) {
            reject(new Error('params参数secret不能为空'));
        }

        fetch('https://api.weixin.qq.com/cgi-bin/token?grant_type=' + params.grant_type +
                '&appid=' + params.appid + '&secret=' + params.secret)
            .then(res => res.json())
            .then(json => resolve(json))
            .catch(err => reject(err));
    });
};

/**
 *
 * 获取jsapi_ticket
 * https: //mp.weixin.qq.com/wiki?t=resource/res_main&id=mp1421141115
 * 附录1 - JS - SDK使用权限签名算法
 *
 * access_token 是 access_token
 * type 是 jsapi
 *
 * @param params
 */
exports.getJsapiTicketAsync = function (params) {
    return new Promise(function (resolve, reject) {
        if (!params) {
            reject(new Error('params参数不能为空'));
        }

        if (!params.access_token) {
            reject(new Error('params参数access_token不能为空'));
        }

        if (!params.type) {
            reject(new Error('params参数type不能为空'));
        }

        fetch('https://api.weixin.qq.com/cgi-bin/ticket/getticket?access_token=' + params.access_token +
                '&type=' + params.type)
            .then(res => res.json())
            .then(json => resolve(json))
            .catch(err => reject(err));
    });
};

/**
 *
 * 获取 signature
 * https: //mp.weixin.qq.com/wiki?t=resource/res_main&id=mp1421141115
 * 附录1 - JS - SDK使用权限签名算法
 *
 * jsapi_ticket 用于签名的 jsapi_ticket
 * timestamp: 必填，生成签名的时间戳
 * nonceStr 必填， 生成签名的随机串
 * url 用于签名的 url ，注意必须动态获取，不能 hardcode
 *
 * @param params
 */
exports.getSignatureAsync = function (params) {
    return new Promise(function (resolve, reject) {
        if (!params) {
            reject(new Error('params参数不能为空'));
        }

        if (!params.jsapi_ticket) {
            reject(new Error('params参数jsapi_ticket不能为空'));
        }

        if (!params.url) {
            reject(new Error('params参数url不能为空'));
        }

        let ret = {
            jsapi_ticket: params.jsapi_ticket,
            nonceStr: exports.createNonceStr,
            timestamp: exports.createTimestamp,
            url: params.url
        };

        const string = exports.raw(ret);

        const jsSHA = require('jssha');
        const shaObj = new jsSHA(string, 'TEXT');

        ret.signature = shaObj.getHash('SHA-1', 'HEX');

        resolve(ret);
    });
};