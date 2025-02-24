<?php
// +----------------------------------------------------------------------
// | 文件: index.php
// +----------------------------------------------------------------------
// | 功能: 提供todo api接口
// +----------------------------------------------------------------------
// | 时间: 2021-11-15 16:20
// +----------------------------------------------------------------------
// | 作者: rangangwei<gangweiran@tencent.com>
// +----------------------------------------------------------------------

namespace app\controller;

use Error;
use Exception;
use app\model\Counters;
use think\Model;
use think\response\Html;
use think\response\Json;
use think\facade\Log;
use think\Request;
use think\facade\Db;

class Index
{

    /**
     * 主页静态页面
     * @return Html
     */
    public function index(): Html
    {
        # html路径: ../view/index.html
        return response(file_get_contents(dirname(dirname(__FILE__)).'/view/index.html'));
    }


    /**
     * 获取todo list
     * @return Json
     */
    public function getCount(): Json
    {
        try {
            $data = (new Counters)->find(1);
            if ($data == null) {
                $count = 0;
            }else {
                $count = $data["count"];
            }
            $res = [
                "code" => 0,
                "data" =>  $count
            ];
            Log::write('getCount rsp: '.json_encode($res));
            return json($res);
        } catch (Error $e) {
            $res = [
                "code" => -1,
                "data" => [],
                "errorMsg" => ("查询计数异常" . $e->getMessage())
            ];
            Log::write('getCount rsp: '.json_encode($res));
            return json($res);
        }
    }


    /**
     * 根据id查询todo数据
     * @param $action `string` 类型，枚举值，等于 `"inc"` 时，表示计数加一；等于 `"reset"` 时，表示计数重置（清零）
     * @return Json
     */
    public function updateCount($action): Json
    {
        try {
            if ($action == "inc") {
                $data = (new Counters)->find(1);
                if ($data == null) {
                    $count = 1;
                }else {
                    $count = $data["count"] + 1;
                }

                $counters = new Counters;
                $counters->create(
                    ["count" => $count, 'id' => 1],
                    ["count", 'id'],
                    true
                );
            }else if ($action == "clear") {
                Counters::destroy(1);
                $count = 0;
            }

            $res = [
                "code" => 0,
                "data" =>  $count
            ];
            Log::write('updateCount rsp: '.json_encode($res));
            return json($res);
        } catch (Exception $e) {
            $res = [
                "code" => -1,
                "data" => [],
                "errorMsg" => ("更新计数异常" . $e->getMessage())
            ];
            Log::write('updateCount rsp: '.json_encode($res));
            return json($res);
        }
    }

    public function login(Request $request)
    {
        try {
            $code = $request->post('code');
            $encryptedData = $request->post('encryptedData');
            $iv = $request->post('iv');

            // 获取 session_key
            $sessionResult = $this->getSessionKey($code);
            if (!$sessionResult) {
                return json(['success' => false, 'message' => '获取session_key失败']);
            }

            $sessionKey = $sessionResult['session_key'];
            $phoneNumber = $this->decryptPhoneNumber($sessionKey, $encryptedData, $iv);
            if (!$phoneNumber) {
                return json(['success' => false, 'message' => '解密手机号失败']);
            }

            // 查找或创建用户
            $user = Db::table('users')->where('phone', $phoneNumber)->find();
            if (!$user) {
                // 如果用户不存在，创建新用户
                $userId = Db::table('users')->insertGetId(['phone' => $phoneNumber]);
            } else {
                $userId = $user['id'];
            }

            // 生成简单的 token
            $token = bin2hex(random_bytes(16)); // 生成一个随机的 token

            // 可选：将 token 存储在数据库中，关联用户
            Db::table('tokens')->insert(['user_id' => $userId, 'token' => $token]);

            return json(['success' => true, 'token' => $token]);

        } catch (\Exception $e) {
            // 捕获异常并返回错误信息
            return json(['success' => false, 'message' => '系统异常', 'error' => $e->getMessage()]);
        }
    }

    private function getSessionKey($code)
    {
        // 调用微信 API 获取 session_key
        $appid = 'wx4d721ed9f5123f6b';
        $secret = '19a65f0a9206fafcad3ac54db5e91ae6';
        $url = "https://api.weixin.qq.com/sns/jscode2session?appid={$appid}&secret={$secret}&js_code={$code}&grant_type=authorization_code";

        try {
            $response = file_get_contents($url);
            $result = json_decode($response, true);

            if (isset($result['errcode']) && $result['errcode'] != 0) {
                \think\facade\Log::error('获取session_key失败：' . json_encode($result));
                return false;
            }

            return $result;
        } catch (\Exception $e) {
            \think\facade\Log::error('请求微信接口异常：' . $e->getMessage());
            return false;
        }
    }

    private function decryptPhoneNumber($sessionKey, $encryptedData, $iv)
    {
        // 使用微信提供的解密算法解密手机号
        // 参考微信文档进行解密
        // 返回解密后的手机号
        // Base64 decode
        $sessionKey = base64_decode($sessionKey);
        $encryptedData = base64_decode($encryptedData);
        $iv = base64_decode($iv);

        // Decrypt
        $decrypted = openssl_decrypt($encryptedData, 'AES-128-CBC', $sessionKey, OPENSSL_RAW_DATA, $iv);

        if ($decrypted === false) {
            return null; // 解密失败
        }

        // Convert decrypted data to array
        $data = json_decode($decrypted, true);

        // Check if the data is valid
        if (isset($data['phoneNumber'])) {
            return $data['phoneNumber']; // 返回手机号
        }

        return null; // 如果没有手机号，返回 null
    }

    private function generateToken($userId)
    {
        // 使用 JWT 生成 token
        $key = config('app.jwt_key'); // 确保 jwt_key 在配置文件中
        $payload = [
            'uid' => $userId,
            'iat' => time(),
            'exp' => time() + 7200 // token 有效期2小时
        ];

        try {
            return \Firebase\JWT\JWT::encode($payload, $key, 'HS256');
        } catch (\Exception $e) {
            \think\facade\Log::error('生成token失败：' . $e->getMessage());
            return false;
        }
    }
}
