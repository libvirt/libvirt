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

    var q = document.getElementById("searchq");
    var newq = document.createElement("input");
    newq.type = "hidden";
    newq.name = "q";
    newq.value = q.value;
    form.appendChild(newq);

    var whats = document.getElementsByName("what");
    var what = "website";
    for (var i = 0; i < whats.length; i++) {
        if (whats[i].checked) {
            what = whats[i].value;
            break;
        }
    }

    if (what == "website" || what == "wiki") {
        form.action = "https://duckduckgo.com/";

        var newsite = document.createElement("input");
        newsite.type = "hidden";
        newsite.name = "sites";
        form.appendChild(newsite);

        if (what == "website") {
            newsite.value = "libvirt.org";
        } else {
            newsite.value = "wiki.libvirt.org";
        }
    } else if (what == "devs" || "users") {
        form.action = "https://lists.libvirt.org/archives/search";

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
