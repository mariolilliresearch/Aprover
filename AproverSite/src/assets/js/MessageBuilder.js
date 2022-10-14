import * as bootstrap from 'bootstrap';
import "./import-jquery.js";
import "jquery-ui-bundle"; // you also need this
import "jquery-ui-bundle/jquery-ui.css";
import draw2d from "draw2d";
import Application from "./Application.js"
import MyConnection from "./MyConnection.js"

window.$ = jQuery;
window.jQuery = jQuery;
window.draw2d = draw2d;


 function decorate() {
     
        var routerToUse = new draw2d.layout.connection.SplineConnectionRouter();
        var app = new Application();
        app.view.installEditPolicy(new draw2d.policy.connection.DragConnectionCreatePolicy2({
            createConnection: function () {
                return new MyConnection();
            }
        }));

    }
window.addEventListener('DOMContentLoaded', decorate)