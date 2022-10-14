import "./import-jquery.js";
import "jquery-ui-bundle"; // you also need this
import "jquery-ui-bundle/jquery-ui.css";
import draw2d from "draw2d";

export default draw2d.shape.basic.Rectangle.extend({
    NAME: "EndPrincipal",

    init: function (attr) {
        this._super($.extend({ bgColor: "#2c3237", height: "20", width: "150" }), attr);

        // Create any Draw2D figure as decoration for the connection

        //


        //this.label.installEditor(new draw2d.ui.LabelInplaceEditor());
    }


});