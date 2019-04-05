function pageload() {
    window.addEventListener('scroll', function(e){
        var distanceY = window.pageYOffset || document.documentElement.scrollTop
        var shrinkOn = 94
        home = document.getElementById("home");
        links = document.getElementById("jumplinks");
        search = document.getElementById("search");
        body = document.getElementById("body");
        if (distanceY > shrinkOn) {
            if (home.className != "navhide") {
                body.className = "navhide"
                home.className = "navhide"
                links.className = "navhide"
                search.className = "navhide"
            }
        } else {
            if (home.className == "navhide") {
                body.className = ""
                home.className = ""
                links.className = ""
                search.className = ""
            }
        }
    });
}
