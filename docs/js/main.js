"use strict";

function pageload() {
    window.addEventListener("scroll", function(e){
        var distanceY = window.pageYOffset || document.documentElement.scrollTop;
        var shrinkOn = 94;
        var home = document.getElementById("home");
        var links = document.getElementById("jumplinks");
        var search = document.getElementById("search");
        var body = document.getElementById("body");
        if (distanceY > shrinkOn) {
            if (home.className != "navhide") {
                body.className = "navhide";
                home.className = "navhide";
                links.className = "navhide";
                search.className = "navhide";
            }
        } else {
            if (home.className == "navhide") {
                body.className = "";
                home.className = "";
                links.className = "";
                search.className = "";
            }
        }
    });

    /* Setting this class makes the advanced search options visible */
    var advancedSearch = document.getElementById("advancedsearch");
    advancedSearch.className = "advancedsearch";

    var simpleSearch = document.getElementById("simplesearch");
    simpleSearch.addEventListener("submit", advancedsearch);
}

function advancedsearch(e) {
    e.preventDefault();
    e.stopPropagation();

    var form = document.createElement("form");
    form.method = "get";

    var newq = document.createElement("input");
    newq.type = "hidden";
    newq.name = "q";
    form.appendChild(newq);

    var q = document.getElementById("searchq");
    var whats = document.getElementsByName("what");
    var what = "website";
    for (var i = 0; i < whats.length; i++) {
        if (whats[i].checked) {
            what = whats[i].value;
            break;
        }
    }

    if (what == "website" || what == "wiki") {
        form.action = "https://google.com/search";
        if (what == "website") {
            newq.value = "site:libvirt.org " + q.value;
        } else {
            newq.value = "site:wiki.libvirt.org " + q.value;
        }
    } else if (what == "devs" || "users") {
        form.action = "https://lists.libvirt.org/archives/search";
        newq.value = q.value;

        var newl = document.createElement("input");
        newl.type = "hidden";
        newl.name = "mlist";
        form.appendChild(newl);

        if (what == "devs") {
            newl.value = "devel@lists.libvirt.org";
        } else {
            newl.value = "users@lists.libvirt.org";
        }
    }

    document.body.appendChild(form);
    form.submit();

    return false;
}

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
