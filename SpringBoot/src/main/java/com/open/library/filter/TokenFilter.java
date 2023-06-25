package com.open.library.filter;

import cn.hutool.http.HttpStatus;
import cn.hutool.json.JSONUtil;
import com.baomidou.mybatisplus.core.toolkit.StringUtils;
import com.open.library.commom.Result;
import com.open.library.entity.User;
import com.open.library.utils.TokenUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Component
public class TokenFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws ServletException, IOException {
        String url = req.getRequestURI();
        // 登陆和注册接口跳过token验证
        if ("/user/register".equals(url) || "/user/login".equals(url)) {
            chain.doFilter(req, res);
            return;
        }

        String token = req.getHeader("token");

        if (StringUtils.isBlank(token)) {
            responseMsg(res, Result.error(String.valueOf(HttpStatus.HTTP_FORBIDDEN), "没找到认证信息！"));
            return;
        }

        User user = TokenUtils.getUser();
        if (user == null) {
            responseMsg(res, Result.error(String.valueOf(HttpStatus.HTTP_FORBIDDEN), "认证信息无法识别！"));
            return;
        }

        chain.doFilter(req, res);
    }

    private void responseMsg(HttpServletResponse res, Object obj) throws IOException {
        res.setContentType("application/json");
        res.setCharacterEncoding("utf-8");
        PrintWriter pw = res.getWriter();
        pw.write(JSONUtil.toJsonStr(obj));
        pw.flush();
        pw.close();
    }


}
