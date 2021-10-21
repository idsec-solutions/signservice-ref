<%-- 
    Document   : user
    Created on : Oct 5, 2011, 1:03:25 PM
    Author     : stefan
--%>

<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>Devmode Signature accept IdP</title>
        <script type="text/javascript" src="script/jquery.js"></script>
        <script type="text/javascript" charset="UTF-8">
            var userData;
            var id;
            var servletUrl = "testid";
            var sigServUrl = "Sign";
//            var sigServUrl = "https://eid2csig.konki.se/signservice/Sign";
            $(document).ready(function() {
                loadUsers();
                id = getQueryVariable("id");                
            });
            
            function loadUsers(){
                var seed=Math.floor(Math.random()*100000001)
                $.getJSON(servletUrl + "?action=userlist", function(json){
                    userData=json;
                    $.each(json, function(i,user){
                        $("<option></option>").html(user.name).appendTo("#userSelect"); 
                    });
                });
            }
            
            function login(){
                var i = document.getElementById('userSelect').selectedIndex;
                var url = servletUrl+"?action=cookie"
                    +"&name=" + encodeURIComponent(userData[i].name)
                    +"&idp=" + encodeURIComponent(userData[i].idp)
                    +"&attr=" + encodeURIComponent(userData[i].attribute)
                    +"&id=" + encodeURIComponent(userData[i].id)
                    +"&email=" +encodeURIComponent(userData[i].email);
                $.getJSON(url, function(){
                    window.location= sigServUrl+"?action=sign&id="+id;
                });
            }
            
            function getQueryVariable(variable) { 
                var query = window.location.search.substring(1); 
                var vars = query.split("&"); 
                for (var i=0;i<vars.length;i++) { 
                    var pair = vars[i].split("="); 
                    if (pair[0] == variable) { 
                        return pair[1]; 
                    } 
                }
                return "";
            } 

            
        </script>
        <style TYPE="text/css" MEDIA=screen>
            body {
                font-family: Verdana, Arial, sans-serif;
                font-size: smaller;
                padding: 20px;
                color: #555;
                width: 90%;
            }

            h1 {
                letter-spacing: 6px;
                font-size: 1.6em;
                color: #6b2c14;
                font-weight: bold;
                margin-bottom: 10px;
            }
            div.main {
                background-color: #f0f0f0;
                width: 400px;
                border: 2px solid #330000;
                padding:20px;
            }

        </style>
    </head>
    <body>
    <center>
        <br/><br/><br/><br/>
        <div class="main">
            <h1> Devmode IdP Service</h1>
            <p>Select the user who agrees to sign 
                <select id="userSelect"></select><br/><br/>
                <input type="button" onclick="login()" value="Sign (Jag skriver under)"></input></p>
        </div>
        
    </center>

    </body>
</html>
