<%-- 
    Document   : signAccept
    Created on : Mar 18, 2012, 5:43:27 PM
    Author     : stefan
--%>

<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>EID 2.0 Central Signing - Sign Accept page</title>

        <script type="text/javascript" charset="UTF-8" src="jquery-1.8.3.js"></script>
        <script type="text/javascript" charset="UTF-8" src="signAccept.js"></script>
        <style TYPE="text/css" MEDIA=screen>
            body {
                font-family: Verdana, Arial, sans-serif;
                font-size: smaller;
                padding: 20px;
                color: #555;
                width: 90%;
            }

            h1 {
                letter-spacing: 2px;
                font-size: 1.2em;
                color:#002c33;
                font-weight: bold;
                margin-bottom: 10px;
            }
            div.main {
                background-color: #fafafa;
                width: 800px;
                border: 2px solid #330000;
                padding:20px;                
            }
            div.pageTitle {
                background-color: #e0e0e0;
                border: 2px solid lightgrey;
                height: 85px;
                vertical-align: middle;
                padding:10px;
            }
            div.inpbar{
                max-height: 30px;
                padding-top: 8px;
                padding-left: 5px;
                background-color: #002c33;
                color: #fafafa;
                font-weight: bold;
            }
            div#messageInfo{
                background-color: white;
                border: 2px solid lightgrey;
                padding: 20px;
                max-height: 400px;
                overflow: auto;
                margin-bottom: 20px;
            }
            img.logo {
                float: right;
                height: 75px;                
            }
            img.element {
                vertical-align: bottom;
                height:18px;
            }
        </style>
    </head>
    <body>
        <div  align="center">
            <br/><br/>
            <div class="main" align="left">
                <div class="pageTitle">
                    <img class="logo" src="logotyp-legitimationsnamnde.png"/>
                    &nbsp;&nbsp;
                    <h1>EID 2.0 TEST Signing Service</h1>                    
                </div>

                <div id="loadImg"><img src="globe32.gif"/></div>

                <div id="generalInfo">
                    <p>Your signature has been requested by&nbsp;<b><span id="requesterName"></span></b></p>
                    <p>By pressing the <img class="element" src="iagreebutton.png"/> button below, you will be asked to identity yourself. Your signature will be created automatically upon successful identification</p>
                </div>
                <div id="messageArea">
                    <div class="inpbar" >Signature request details from&nbsp;<span id="requesterName2"></span></div>
                    <div id="messageInfo"></div>
                </div>
                <div id ="buttonArea">
                    <input type="button" onclick="sign()" value="I agree to sign"/> 
                    &nbsp;&nbsp;
                    <input type="button" onclick="decline()" value="Exit without signing"/>             
                </div>            
            </div>
        </div>
    </body>
</html>
