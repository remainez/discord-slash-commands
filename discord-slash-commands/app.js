require('dotenv').config();
const nacl = require('tweetnacl');
const commands = require('./modules/commands.js')

/**
 * Event doc: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html#api-gateway-simple-proxy-for-lambda-input-format
 * @param {Object} event - API Gateway Lambda Proxy Input Format
 * Context doc: https://docs.aws.amazon.com/lambda/latest/dg/nodejs-prog-model-context.html 
 * @param {Object} context
 * Return doc: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
 * @returns {Object} object - API Gateway Lambda Proxy Output Format
 */
exports.lambdaHandler = async (event, context) => {
    const signature = event.headers['x-signature-ed25519'];
    const timestamp = event.headers['x-signature-timestamp'];
    const body = event.body;

    if (!isVerify(signature, timestamp, body)) {
        // discord以外のリクエストの場合は401
        return responseGenerate(401, {
            message: 'invalid request signature'
        });
    }

    const req = JSON.parse(body);

    if (req['type'] === 1) {
        return responseGenerate(200, {
            type: 1
        });
    } else if (req['type'] === 2) {
        try {
            // 通常のコマンドリクエスト
            return responseGenerate(200, {
                type: 4,
                data: {
                    content: commands[req['data']['name']](optionToArray(req['data']['options']), req['member'])
                }
            });
        } catch (e) {
            console.error(e);
            return responseGenerate(200, {
                type: 4,
                data: {
                    content: 'コマンドが実行出来ませんでした'
                }
            });
        }
    }
    return responseGenerate(404, {
        message: 'not found'
    });
};

/**
 * 認証
 * @param {string} signature x-signature-ed25519
 * @param {string} timestamp x-signature-timestamp
 * @param {string} body リクエストボティ
 * @returns {boolean} 認証結果
 */
const isVerify = (signature, timestamp, body) => {
    return nacl.sign.detached.verify (
        Buffer.from(timestamp + body),
        Buffer.from(signature, 'hex'),
        Buffer.from(process.env.PUBLIC_KEY, 'hex')
    );
};

/**
 * レスポンス生成
 * @param {string} code ステータスコード
 * @param {array} body レスポンスボティ
 * @returns {array} レスポンス配列
 */
const responseGenerate = (code, body) => {
    return {
        'statusCode': code,
        'body': JSON.stringify(body)
    };
};

/**
 * オプションの連想配列化
 * @param {array} options オプション配列
 * @returns {array} result オプション連想配列 {オプション名: 値}
 */
const optionToArray = (options) => {
    let result = [];
    if (options == null) {
        return result;
    }
    for (opt of options) {
        result[opt['name']] = opt['value'];
    }
    return result;
};
