"use strict";

function fetchRSS() {
    if (document.location.protocol == "file:")
        return;

    var planet = document.getElementById("planet");
    if (planet === null)
        return;

    var req = new XMLHttpRequest();
    req.open("GET", "https://planet.virt-tools.org/atom.xml");
    req.setRequestHeader("Accept", "application/atom+xml, text/xml");
    req.onerror = function(e) {
        if (this.statusText != "")
            console.error(this);
    };
    req.onload = function(e) {
        if (this.readyState !== 4)
            return;

        if (this.status != 200) {
            console.error(this.statusText);
            return;
        }

        if (this.responseXML === null) {
            console.error("Atom response is not an XML");
            return;
        }

        var dl = document.createElement("dl");
        var dateOpts = { day: "numeric", month: "short", year: "numeric"};

        var entries = this.responseXML.querySelectorAll("feed > entry:not(:nth-of-type(1n+5))");

        entries.forEach(function(e) {
            var name = e.querySelector("author > name").textContent;
            var title = e.querySelector("title").textContent;
            var updated = e.querySelector("updated").textContent;
            var link = e.querySelector("link").attributes.href.textContent;

            var a = document.createElement("a");
            a.href = link;
            a.innerText = title;

            var dt = document.createElement("dt");
            dt.appendChild(a);
            dl.appendChild(dt);

            var date = new Date(updated);
            date = date.toLocaleDateString("default", dateOpts);

            var dd = document.createElement("dd");
            dd.innerText = ` by ${name} on ${date}`;

            dl.appendChild(dd);
        });

        planet.appendChild(dl);
    };
    req.send();
}

window.addEventListener("load", function() { fetchRSS() });
