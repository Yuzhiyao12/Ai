<?php
namespace app\controller;

use think\Controller;
use think\Request;
use think\facade\Db;

class Login extends Controller
{
    public function index(Request $request)
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
        $secret = 'YOUR_SECRET';
        $url = "https://api.weixin.qq.com/sns/jscode2session?appid={$appid}&secret={$secret}&js_code={$code}&grant_type=authorization_code";

        $response = file_get_contents($url);
        return json_decode($response, true);
    }

    private function decryptPhoneNumber($sessionKey, $encryptedData, $iv)
    {
        // 使用微信提供的解密算法解密手机号
        // 参考微信文档进行解密
        // 返回解密后的手机号
    }

    private function generateToken($userId)
    {
        // 生成 token 的逻辑
        return 'generated_token';
    }
}