<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
 
 <%
	String path = request.getContextPath();
	String basePath = request.getScheme()+"://"+request.getServerName()+":"+request.getServerPort()+path+"/";
%>
 
<!doctype html>
<html>
  <head>
    <title>JavaScript RSA Encryption</title>
    <base href="<%=basePath %>" />
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
	
    <script type="text/javascript">
    	window.location = "servlet/test";
    </script>
  </head>
  <body>
  	<input id="password" /><input type="button" onclick="javascript:rsalogin()" value="ＧＯ"/>
  </body>
</html>