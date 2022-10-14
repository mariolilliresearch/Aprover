import * as bootstrap from 'bootstrap';
import * as draw2d from "draw2d";
import "./import-jquery.js";
import "jquery-ui-bundle"; // you also need this
import "jquery-ui-bundle/jquery-ui.css";
import draw2d from "draw2d";

window.$ = jQuery;
window.jQuery = jQuery;
window.draw2d = draw2d;


let arrow = document.querySelectorAll(".arrow");
for (var i = 0; i < arrow.length; i++) {
    arrow[i].addEventListener("click", (e) => {
        let arrowParent = e.target.parentElement.parentElement;//selecting main parent of arrow
        arrowParent.classList.toggle("showMenu");
    });

}
let sidebar = document.querySelector(".sidebar");
let sidebarBtnSend = document.querySelector(".sender");
let sidebarBtnRec = document.querySelector(".receiver");
let sidebarBtnAtk = document.querySelector(".attacker");
let sidebarBtnServ = document.querySelector(".server");

var userSelect = 0;

sidebarBtnSend.addEventListener("click", () => {
    var element = event.currentTarget;
    element.clicks = (element.clicks || 0) + 1;
    if (userSelect != 0) {
        userSelect = 0;
        element.clicks = 0;
        sidebarBtnSend.classList.toggle("active");
        sidebarBtnRec.classList.remove("active");
        sidebarBtnAtk.classList.remove("active");
        sidebarBtnServ.classList.remove("active");
        sidebar.classList.toggle("senderdb");
        sidebar.classList.remove("receiverdb");
        sidebar.classList.remove("attackerdb");
        sidebar.classList.remove("serverdb");
    } else {
        sidebar.classList.toggle("close");
    };
    console.log(element.clicks);


});

sidebarBtnRec.addEventListener("click", () => {

    var element = event.currentTarget;
    element.clicks = (element.clicks || 0) + 1;
    if (userSelect != 1) {
        userSelect = 1;
        element.clicks = 0;
        sidebarBtnSend.classList.remove("active");
        sidebarBtnRec.classList.toggle("active");
        sidebarBtnAtk.classList.remove("active");
        sidebarBtnServ.classList.remove("active");
        sidebar.classList.remove("senderdb");
        sidebar.classList.toggle("receiverdb");
        sidebar.classList.remove("attackerdb");
        sidebar.classList.remove("serverdb");
    } else {
        sidebar.classList.toggle("close");
    };
    console.log(element.clicks);

});

sidebarBtnAtk.addEventListener("click", () => {

    var element = event.currentTarget;
    element.clicks = (element.clicks || 0) + 1;
    if (userSelect != 2) {
        userSelect = 2;
        element.clicks = 0;
        sidebarBtnSend.classList.remove("active");
        sidebarBtnRec.classList.remove("active");
        sidebarBtnAtk.classList.toggle("active");
        sidebarBtnServ.classList.remove("active");
        sidebar.classList.remove("senderdb");
        sidebar.classList.remove("receiverdb");
        sidebar.classList.toggle("attackerdb");
        sidebar.classList.remove("serverdb");
    } else {
        sidebar.classList.toggle("close");
    };
    console.log(element.clicks);

});

sidebarBtnServ.addEventListener("click", () => {

    var element = event.currentTarget;
    element.clicks = (element.clicks || 0) + 1;
    if (userSelect != 3) {
        userSelect = 3;
        element.clicks = 0;
        sidebarBtnSend.classList.remove("active");
        sidebarBtnRec.classList.remove("active");
        sidebarBtnAtk.classList.remove("active");
        sidebarBtnServ.classList.toggle("active");
        sidebar.classList.remove("senderdb");
        sidebar.classList.remove("receiverdb");
        sidebar.classList.remove("attackerdb");
        sidebar.classList.toggle("serverdb");
    } else {
        sidebar.classList.toggle("close");
    };
    console.log(element.clicks);

});