import axios from 'axios'
import router from "../router";

const request = axios.create({
    baseURL: '/api',
    timeout: 5000
})

// request 拦截器
// 可以自请求发送前对请求做一些处理
// 比如统一加token，对请求参数统一加密
request.interceptors.request.use(config => {
    config.headers['Content-Type'] = 'application/json;charset=utf-8';
    // 登陆和注册无需加token
    if (config.url === 'user/login' || config.url === 'user/register') {
        return config
    }

    let userJson = sessionStorage.getItem("user")
    if (userJson) {
        // 添加token
        config.headers['token'] = JSON.parse(userJson).token;
    } else {
        // 未登陆跳转到登录页
        router.push("/login")
    }

    return config
}, error => {
    return Promise.reject(error)
});

// response 拦截器
// 可以在接口响应后统一处理结果
request.interceptors.response.use(
    response => {
        let res = response.data;
        // 如果是返回的文件
        if (response.config.responseType === 'blob') {
            return res
        }
        // 兼容服务端返回的字符串数据
        if (typeof res === 'string') {
            res = res ? JSON.parse(res) : res
        }
        // 发现未认证返回到登录页
        if (res.code === '403') {
            router.push("/login")
        }

        return res;
    },
    error => {
        console.log('err' + error) // for debug
        return Promise.reject(error)
    }
)


export default request

