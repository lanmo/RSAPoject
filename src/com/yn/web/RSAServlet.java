package com.yn.web;

import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.yn.utils.RSAUtil;

public class RSAServlet extends HttpServlet {

	/** (用一句话描述这个变量表示什么) */
	private static final long serialVersionUID = -6149101171236706167L;

	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		try {
			RSAUtil.generateKeyPair();
			RSAPrivateKey privateKey =  (RSAPrivateKey) RSAUtil.getKeyPair().getPrivate();
			
			req.setAttribute("m", privateKey.getModulus().toString(16));
			req.setAttribute("d", privateKey.getPrivateExponent().toString(16));
			
			req.getRequestDispatcher("/index.jsp").forward(req, resp);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		
		String password = request.getParameter("password");
		try {
			byte[] encrypt = RSAUtil.encrypt(RSAUtil.getKeyPair().getPublic(), password.getBytes());
			BigInteger b = new BigInteger(encrypt);
			String result = b.toString(16);
			response.setContentType("text/json;charset=utf-8");
	        PrintWriter pw = response.getWriter();
	        result = "{\"result\":\""+result + "\"}";
	        pw.write(result);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}

}

