package com.coding404.jwt.security.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public class FilterTwo implements Filter{

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		System.out.println("==========filter Two 실행됨==========>");
		
		//토큰의 유효성 검사 or 로그인 시도
		
		
		
		chain.doFilter(request, response); //다음 필터로의 연결
		
	}

	
	
	
}
