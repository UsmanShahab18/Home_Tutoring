document.addEventListener("DOMContentLoaded", function () {
    const menuCheckbox = document.getElementById("menu-bar");
    const label = document.querySelector("label[for='menu-bar']");
    const header = document.querySelector("header");

    function applyResponsiveHeader() {
        const width = window.innerWidth;

        if (width <= 991) {

        } else {

        }
    }

    window.addEventListener("resize", applyResponsiveHeader);

    applyResponsiveHeader();

    function applyResponsiveFooter() {
        const footerCols = document.querySelectorAll(".footer-col");
        const row = document.querySelector(".footer .row");

        if (window.innerWidth <= 767) {
            row.style.flexDirection = "column";
            footerCols.forEach(col => col.style.width = "100%");
        } else if (window.innerWidth <= 991) {
            row.style.flexDirection = "row";
            footerCols.forEach(col => col.style.width = "50%");
        } else {
            row.style.flexDirection = "row";
            footerCols.forEach(col => col.style.width = "25%");
        }
    }

    applyResponsiveFooter();

    window.addEventListener("resize", applyResponsiveFooter);
});
