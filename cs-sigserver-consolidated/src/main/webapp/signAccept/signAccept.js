var sigRequestServletUrl = "SigRequest";
var sigReuestRedirectUrl;
var sigReuestDeclineUrl;
var signingInstanceNonce;


/**
 * Execute on page load
 */
$(document).ready(function() {
    $("#loadImg").show();
    $("#generalInfo").hide();
    $("#messageArea").hide();
    $("#buttonArea").hide();
    signingInstanceNonce = getQueryVariable("id");
    if (signingInstanceNonce.length>0){
        getStatus();        
    }
});


function getStatus(){
    $.getJSON(sigRequestServletUrl+'?action=status&id='+ signingInstanceNonce, function(data) {
        sigReuestRedirectUrl=data.sigReuestRedirectUrl;
        sigReuestDeclineUrl=data.sigReuestDeclineUrl;        
        $("#requesterName").append(data.requesterName);
        $("#requesterName2").append(data.requesterName);
        loadMessage();
    });    
}

function loadMessage (){
    $("#messageInfo").load(sigRequestServletUrl + "?action=signmessage&id="+signingInstanceNonce);
    $("#loadImg").hide();
    $("#messageArea").show();    
    $("#generalInfo").show();
    $("#buttonArea").show();
}

function sign(){
    window.location=sigReuestRedirectUrl;
}

function decline(){
    window.location=sigReuestDeclineUrl;
}

/**
 * Returns the value of the specified url query string found in the url used to load this page
 */
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

