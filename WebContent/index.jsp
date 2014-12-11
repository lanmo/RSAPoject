<%@ page language="java" contentType="text/html; charset=UTF-8" isELIgnored="false"
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
    <script src="http://code.jquery.com/jquery-1.8.3.min.js"></script>
    <script type="text/javascript" src="RSA/js/RSA.js"></script>
	<script type="text/javascript" src="RSA/js/BigInt.js"></script>
	<script type="text/javascript" src="RSA/js/Barrett.js"></script>
	
    <script type="text/javascript">
	    function rsalogin(){
	    	var thisPwd = $("#password").val();
	    	bodyRSA();
	    	$.ajax({
	           	 url: 'servlet/test',
	           	 datatype: "json",
	          	  type: 'post',
	           	 data:{ 'password': thisPwd},
	           	 success: function (data) {   //成功后回调
	            	console.log(data.result);
   			   		var result = decryptedString(key,data.result);
   			   		console.log(reverse(result));
	          	  },
	           	 error: function(e){    //失败后回调
	                console.log(e);
	           	 }
	  	 	 });
  	  }
	    
	    function reverse(str) {
	    	var abc = "";
	    	for(var i=str.length-1; i>=0; --i) {
	    		abc += str.charAt(i);
	    	}
	    	
	    	return abc;
	    }
	    
	    var key ;
	    function bodyRSA(){
	    	setMaxDigits(130);
	    	var enexpo = "";
	    	var dececpo = '${d}';
	    	var mod = '${m}';
	    	console.log(dececpo+",mod="+mod);
	      	key = new RSAKeyPair(enexpo, dececpo, mod); 
	    }
    
    </script>
  </head>
  <body>
  	<input id="password" /><input type="button" onclick="javascript:rsalogin()" value="ＧＯ"/>
  </body>
</html>