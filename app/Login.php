<?php
namespace app\controller;

use think\Controller;
use think\Request;
use think\facade\Db;

class Login extends Controller
{
    public function login(Request $request)
    {
        
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

        // 生成 token（可以使用 JWT 或其他方式）
        $token = $this->generateToken($userId);

        return json(['success' => true, 'token' => $token]);
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